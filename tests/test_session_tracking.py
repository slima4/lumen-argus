"""Tests for session/conversation tracking.

Covers:
- Session extraction: header > metadata dict > metadata string > fingerprint
- Claude Code metadata.user_id dict parsing (account_id, device_id, session_id)
- User-Agent / client_name extraction
- Git branch + OS platform extraction from system prompt
- Fingerprint stability and uniqueness
- Working directory extraction
- Source IP and API key hashing
- AuditEntry session fields
- Pipeline session passthrough
- Analytics store with all session columns
"""

import hashlib
import hmac
import unittest
from unittest.mock import MagicMock

from lumen_argus.models import AuditEntry, Finding, SessionContext
from lumen_argus.session import (
    _GIT_BRANCH_PATTERNS,
    _OS_PLATFORM_PATTERNS,
    _derive_session_fingerprint,
    _extract_system_field,
    _extract_working_directory,
    _get_system_text,
    parse_user_agent_metadata,
)
from lumen_argus.session import (
    extract_session as _extract_session,
)
from lumen_argus_core.clients import identify_client
from tests.helpers import StoreTestCase


class _HandlerShim:
    """Thin shim: adapts module-level _extract_session to handler.method() pattern."""

    def __init__(self, client_address=("127.0.0.1", 54321)):
        self.client_address = client_address

    def _extract_session(self, data, provider, headers, *, hmac_key=b""):
        return _extract_session(data, provider, headers, self.client_address[0], hmac_key=hmac_key)


def _make_handler(client_address=("127.0.0.1", 54321)):
    return _HandlerShim(client_address)


# --- Session extraction priority ---


class TestSessionExtractionPriority(unittest.TestCase):
    """Session ID priority: explicit header > metadata dict > metadata string > fingerprint."""

    def test_explicit_header_highest_priority(self):
        """x-session-id header wins over everything."""
        handler = _make_handler()
        data = {
            "metadata": {"user_id": {"account_uuid": "acct-1", "session_id": "meta-sess"}},
            "system": "You are helpful.",
            "messages": [{"role": "user", "content": "hello"}],
        }
        ctx = handler._extract_session(data, "anthropic", {"x-session-id": "hdr-sess-42"})
        self.assertEqual(ctx.session_id, "hdr-sess-42")

    def test_metadata_json_string_user_id(self):
        """Claude Code sends user_id as a JSON string containing a dict."""
        handler = _make_handler()
        data = {
            "metadata": {
                "user_id": '{"device_id":"dd7554a9ef88","account_uuid":"dbd6eafd-726c","session_id":"7ef7b337-2fed"}'
            },
            "system": "You are helpful.",
            "messages": [{"role": "user", "content": "hi"}],
        }
        ctx = handler._extract_session(data, "anthropic", {})
        self.assertEqual(ctx.session_id, "7ef7b337-2fed")
        self.assertEqual(ctx.account_id, "dbd6eafd-726c")
        self.assertEqual(ctx.device_id, "dd7554a9ef88")

    def test_metadata_dict_session_id(self):
        """Native dict metadata.user_id also works (forward-compat)."""
        handler = _make_handler()
        data = {
            "metadata": {
                "user_id": {
                    "account_uuid": "dbd6eafd-726c",
                    "device_id": "dd7554a9",
                    "session_id": "7ef7b337-2fed",
                }
            },
            "system": "You are helpful.",
            "messages": [{"role": "user", "content": "hi"}],
        }
        ctx = handler._extract_session(data, "anthropic", {})
        self.assertEqual(ctx.session_id, "7ef7b337-2fed")
        self.assertEqual(ctx.account_id, "dbd6eafd-726c")
        self.assertEqual(ctx.device_id, "dd7554a9")

    def test_metadata_invalid_json_string_treated_as_account(self):
        """A string starting with { that isn't valid JSON is used as account_id."""
        handler = _make_handler()
        data = {
            "metadata": {"user_id": "{not-valid-json"},
            "system": "prompt",
            "messages": [{"role": "user", "content": "hi"}],
        }
        ctx = handler._extract_session(data, "anthropic", {})
        self.assertEqual(ctx.account_id, "{not-valid-json")

    def test_metadata_dict_fields_with_explicit_header(self):
        """When header overrides session_id, account_id/device_id still extracted."""
        handler = _make_handler()
        data = {
            "metadata": {"user_id": '{"account_uuid":"acct-uuid","device_id":"dev-id","session_id":"should-not-win"}'},
            "messages": [{"role": "user", "content": "hi"}],
        }
        ctx = handler._extract_session(data, "anthropic", {"x-session-id": "hdr-wins"})
        self.assertEqual(ctx.session_id, "hdr-wins")
        self.assertEqual(ctx.account_id, "acct-uuid")
        self.assertEqual(ctx.device_id, "dev-id")

    def test_metadata_string_user_id(self):
        """Simple string metadata.user_id goes to account_id, no session_id from metadata."""
        handler = _make_handler()
        data = {
            "metadata": {"user_id": "simple-user-string"},
            "system": "prompt",
            "messages": [{"role": "user", "content": "hi"}],
        }
        ctx = handler._extract_session(data, "anthropic", {})
        self.assertEqual(ctx.account_id, "simple-user-string")
        # session_id falls through to fingerprint
        self.assertTrue(ctx.session_id.startswith("fp:"))

    def test_openai_user_field(self):
        """OpenAI user field populates account_id."""
        handler = _make_handler()
        data = {
            "user": "openai_org_xyz",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "hi"},
            ],
        }
        ctx = handler._extract_session(data, "openai", {})
        self.assertEqual(ctx.account_id, "openai_org_xyz")

    def test_opencode_zen_session_from_header(self):
        """OpenCode Zen sends x-opencode-session with sortable session ID."""
        handler = _make_handler()
        data = {"messages": [{"role": "user", "content": "hello"}]}
        ctx = handler._extract_session(data, "openai", {"x-opencode-session": "ses_ff0a1b2c3d4eAbCdEfGhIjKlMn"})
        self.assertEqual(ctx.session_id, "ses_ff0a1b2c3d4eAbCdEfGhIjKlMn")

    def test_opencode_non_hosted_session_from_affinity(self):
        """OpenCode non-hosted providers send x-session-affinity."""
        handler = _make_handler()
        data = {"messages": [{"role": "user", "content": "hello"}]}
        ctx = handler._extract_session(data, "anthropic", {"x-session-affinity": "ses_aabbccdd1122XyZaBcDeFgHiJk"})
        self.assertEqual(ctx.session_id, "ses_aabbccdd1122XyZaBcDeFgHiJk")

    def test_explicit_session_id_beats_opencode_headers(self):
        """x-session-id header has higher priority than x-opencode-session."""
        handler = _make_handler()
        data = {"messages": [{"role": "user", "content": "hello"}]}
        ctx = handler._extract_session(
            data,
            "openai",
            {
                "x-session-id": "explicit-123",
                "x-opencode-session": "ses_ff0a1b2c3d4eAbCdEfGhIjKlMn",
            },
        )
        self.assertEqual(ctx.session_id, "explicit-123")

    def test_opencode_session_beats_fingerprint(self):
        """x-opencode-session takes priority over derived fingerprint."""
        handler = _make_handler()
        data = {
            "system": "You are helpful.",
            "messages": [{"role": "user", "content": "What is 2+2?"}],
        }
        ctx = handler._extract_session(data, "anthropic", {"x-opencode-session": "ses_realid"})
        self.assertEqual(ctx.session_id, "ses_realid")
        self.assertFalse(ctx.session_id.startswith("fp:"))

    def test_fingerprint_fallback(self):
        """Without header or metadata, derives fp: fingerprint."""
        handler = _make_handler()
        data = {
            "system": "You are a helpful assistant.",
            "messages": [
                {"role": "user", "content": "What is 2+2?"},
                {"role": "assistant", "content": "4"},
            ],
        }
        ctx = handler._extract_session(data, "anthropic", {})
        self.assertTrue(ctx.session_id.startswith("fp:"))
        self.assertEqual(len(ctx.session_id), 15)  # "fp:" + 12 hex chars

    def test_none_data_returns_empty(self):
        """None data produces empty session_id."""
        handler = _make_handler()
        ctx = handler._extract_session(None, "anthropic", {})
        self.assertEqual(ctx.session_id, "")

    def test_no_prefixes_on_session_id(self):
        """Session IDs from header and metadata have no meta:/hdr: prefix."""
        handler = _make_handler()
        ctx1 = handler._extract_session({}, "anthropic", {"x-session-id": "abc123"})
        self.assertEqual(ctx1.session_id, "abc123")

        data = {
            "metadata": {"user_id": {"session_id": "uuid-from-provider"}},
            "messages": [],
        }
        ctx2 = handler._extract_session(data, "anthropic", {})
        self.assertEqual(ctx2.session_id, "uuid-from-provider")


# --- Client name extraction ---


class TestClientName(unittest.TestCase):
    """Client identification via identify_client() and session extraction."""

    def test_claude_code_identified(self):
        cid, name, ver, _ = identify_client("claude-code/1.2.3 python/3.12")
        self.assertEqual(cid, "claude_code")
        self.assertEqual(name, "Claude Code")
        self.assertEqual(ver, "1.2.3")

    def test_cursor_identified(self):
        cid, _, ver, _ = identify_client("Cursor/0.45.1")
        self.assertEqual(cid, "cursor")
        self.assertEqual(ver, "0.45.1")

    def test_unknown_passthrough(self):
        cid, _, _, _ = identify_client("python-requests/2.31.0")
        self.assertEqual(cid, "python-requests/2.31.0")

    def test_browser_skipped(self):
        cid, _, _, _ = identify_client("Mozilla/5.0 (Macintosh; Intel Mac OS X)")
        self.assertEqual(cid, "")

    def test_empty_ua(self):
        cid, _, _, _ = identify_client("")
        self.assertEqual(cid, "")

    def test_client_name_in_session(self):
        """extract_session populates client_name with normalized registry ID."""
        handler = _make_handler()
        ctx = handler._extract_session({}, "anthropic", {"user-agent": "claude-code/1.5.0 python/3.12"})
        self.assertEqual(ctx.client_name, "claude_code")


# --- System text extraction helper ---


class TestGetSystemText(unittest.TestCase):
    """_get_system_text helper for all providers."""

    def test_anthropic_string(self):
        self.assertEqual(_get_system_text({"system": "Hello"}, "anthropic"), "Hello")

    def test_anthropic_list(self):
        data = {"system": [{"text": "A"}, {"text": "B"}]}
        self.assertEqual(_get_system_text(data, "anthropic"), "A\nB")

    def test_openai_system_message(self):
        data = {"messages": [{"role": "system", "content": "Sys"}, {"role": "user", "content": "hi"}]}
        self.assertEqual(_get_system_text(data, "openai"), "Sys")

    def test_gemini(self):
        data = {"systemInstruction": {"parts": [{"text": "Gemini sys"}]}}
        self.assertEqual(_get_system_text(data, "gemini"), "Gemini sys")

    def test_unknown_provider(self):
        self.assertEqual(_get_system_text({}, "unknown"), "")


# --- Git branch + OS platform extraction ---


class TestSystemFieldExtraction(unittest.TestCase):
    """Git branch and OS platform extraction from system prompts."""

    def test_git_branch_claude_code(self):
        data = {"system": "Info.\nCurrent branch: main\nMore info.", "messages": []}
        self.assertEqual(_extract_system_field(data, "anthropic", _GIT_BRANCH_PATTERNS), "main")

    def test_git_branch_generic(self):
        data = {"system": "branch: feature/auth\nEnd.", "messages": []}
        self.assertEqual(_extract_system_field(data, "anthropic", _GIT_BRANCH_PATTERNS), "feature/auth")

    def test_os_platform_claude_code(self):
        data = {"system": "Platform: darwin\nShell: zsh", "messages": []}
        self.assertEqual(_extract_system_field(data, "anthropic", _OS_PLATFORM_PATTERNS), "darwin")

    def test_os_platform_generic(self):
        data = {"system": "OS: linux\nEnd.", "messages": []}
        self.assertEqual(_extract_system_field(data, "anthropic", _OS_PLATFORM_PATTERNS), "linux")

    def test_no_match_returns_empty(self):
        data = {"system": "No branch or platform info here.", "messages": []}
        self.assertEqual(_extract_system_field(data, "anthropic", _GIT_BRANCH_PATTERNS), "")

    def test_openai_system_message(self):
        data = {"messages": [{"role": "system", "content": "Current branch: develop\nPlatform: win32"}]}
        self.assertEqual(_extract_system_field(data, "openai", _GIT_BRANCH_PATTERNS), "develop")
        self.assertEqual(_extract_system_field(data, "openai", _OS_PLATFORM_PATTERNS), "win32")

    def test_full_session_extraction_with_branch_and_platform(self):
        """_extract_session populates git_branch and os_platform."""
        handler = _make_handler()
        data = {
            "system": "Claude Code.\nPrimary working directory: /dev/repo\nCurrent branch: main\nPlatform: darwin",
            "messages": [{"role": "user", "content": "hi"}],
        }
        ctx = handler._extract_session(data, "anthropic", {})
        self.assertEqual(ctx.working_directory, "/dev/repo")
        self.assertEqual(ctx.git_branch, "main")
        self.assertEqual(ctx.os_platform, "darwin")


# --- Fingerprint tests (unchanged logic, just verify still works) ---


class TestFingerprintStability(unittest.TestCase):
    def test_stable_across_growing_conversation(self):
        base = {"system": "Sys", "messages": [{"role": "user", "content": "Q"}, {"role": "assistant", "content": "A"}]}
        ext = {
            "system": "Sys",
            "messages": [
                {"role": "user", "content": "Q"},
                {"role": "assistant", "content": "A"},
                {"role": "user", "content": "Q2"},
                {"role": "assistant", "content": "A2"},
            ],
        }
        self.assertEqual(
            _derive_session_fingerprint(base, "anthropic"),
            _derive_session_fingerprint(ext, "anthropic"),
        )

    def test_different_content_different_fp(self):
        fp1 = _derive_session_fingerprint({"system": "S", "messages": [{"role": "user", "content": "A"}]}, "anthropic")
        fp2 = _derive_session_fingerprint({"system": "S", "messages": [{"role": "user", "content": "B"}]}, "anthropic")
        self.assertNotEqual(fp1, fp2)


# --- Working directory extraction ---


class TestWorkingDirectoryExtraction(unittest.TestCase):
    def test_claude_code(self):
        data = {"system": "Primary working directory: /Users/dev/myproject\n", "messages": []}
        self.assertEqual(_extract_working_directory(data, "anthropic"), "/Users/dev/myproject")

    def test_cursor(self):
        data = {"system": "You are working in: /home/user/app\n", "messages": []}
        self.assertEqual(_extract_working_directory(data, "anthropic"), "/home/user/app")

    def test_openai(self):
        data = {"messages": [{"role": "system", "content": "cwd: /opt/proj"}]}
        self.assertEqual(_extract_working_directory(data, "openai"), "/opt/proj")

    def test_opencode_env_block(self):
        """OpenCode uses 'Working directory:' inside <env> tags."""
        system = (
            "You are powered by the model named minimax-m2.5-free.\n"
            "<env>\n"
            "  Working directory: /Users/slim/dev/myproject\n"
            "  Workspace root folder: /Users/slim/dev/myproject\n"
            "  Is directory a git repo: yes\n"
            "  Platform: darwin\n"
            "</env>"
        )
        # OpenCode Zen uses Anthropic messages format for some models
        data = {"system": [{"type": "text", "text": system}], "messages": []}
        self.assertEqual(_extract_working_directory(data, "anthropic"), "/Users/slim/dev/myproject")

    def test_opencode_openai_format(self):
        """OpenCode with OpenAI-format models."""
        system = "<env>\n  Working directory: /home/user/project\n  Platform: linux\n</env>"
        data = {"messages": [{"role": "system", "content": system}]}
        self.assertEqual(_extract_working_directory(data, "openai"), "/home/user/project")

    def test_strips_quotes(self):
        data = {"system": 'Primary working directory: "/Users/dev/my project"', "messages": []}
        self.assertEqual(_extract_working_directory(data, "anthropic"), "/Users/dev/my project")


# --- Source IP and API key hash ---


class TestSourceIPAndAPIKey(unittest.TestCase):
    def test_xff_first_ip(self):
        handler = _make_handler()
        ctx = handler._extract_session({}, "anthropic", {"x-forwarded-for": "192.168.1.42, 10.0.0.1"})
        self.assertEqual(ctx.source_ip, "192.168.1.42")

    def test_fallback_to_client_address(self):
        handler = _make_handler(client_address=("10.0.0.5", 12345))
        ctx = handler._extract_session({}, "anthropic", {})
        self.assertEqual(ctx.source_ip, "10.0.0.5")

    def test_api_key_hash_truncated(self):
        handler = _make_handler()
        ctx = handler._extract_session({}, "anthropic", {"x-api-key": "sk-ant-test123"}, hmac_key=b"test-key")
        expected = hmac.new(b"test-key", b"sk-ant-test123", hashlib.sha256).hexdigest()[:16]
        self.assertEqual(ctx.api_key_hash, expected)
        self.assertEqual(len(ctx.api_key_hash), 16)

    def test_bearer_token_stripped(self):
        handler = _make_handler()
        ctx = handler._extract_session({}, "anthropic", {"authorization": "Bearer sk-test"}, hmac_key=b"test-key")
        expected = hmac.new(b"test-key", b"sk-test", hashlib.sha256).hexdigest()[:16]
        self.assertEqual(ctx.api_key_hash, expected)

    def test_no_key_no_hash(self):
        handler = _make_handler()
        ctx = handler._extract_session({}, "anthropic", {})
        self.assertEqual(ctx.api_key_hash, "")


# --- AuditEntry ---


class TestAuditEntrySession(unittest.TestCase):
    def test_all_session_fields_in_to_dict(self):
        entry = AuditEntry(
            timestamp="2026-03-19T15:09:47.517Z",
            request_id=1,
            provider="anthropic",
            model="opus",
            endpoint="/v1/messages",
            action="alert",
            account_id="acct-uuid",
            api_key_hash="deadbeef12345678",
            session_id="sess-id",
            device_id="dev-id",
            source_ip="10.0.0.1",
            working_directory="/dev/repo",
            git_branch="main",
            os_platform="darwin",
            client_name="claude-code/1.0",
        )
        d = entry.to_dict()
        self.assertEqual(d["account_id"], "acct-uuid")
        self.assertEqual(d["session_id"], "sess-id")
        self.assertEqual(d["device_id"], "dev-id")
        self.assertEqual(d["git_branch"], "main")
        self.assertEqual(d["os_platform"], "darwin")
        self.assertEqual(d["client_name"], "claude-code/1.0")
        # api_key_hash is NOT serialized to audit log (security: credential-adjacent data)
        self.assertNotIn("api_key_hash", d)

    def test_empty_fields_omitted(self):
        entry = AuditEntry(
            timestamp="t",
            request_id=1,
            provider="",
            model="",
            endpoint="/",
            action="pass",
        )
        d = entry.to_dict()
        for key in (
            "account_id",
            "session_id",
            "device_id",
            "source_ip",
            "working_directory",
            "git_branch",
            "os_platform",
            "client_name",
            "api_key_hash",
        ):
            self.assertNotIn(key, d)


# --- Analytics store ---


class TestAnalyticsStoreSession(StoreTestCase):
    def _finding(self):
        return Finding(
            detector="secrets",
            type="aws_access_key",
            severity="critical",
            location="messages[0].content",
            value_preview="AKIA****",
            matched_value="AKIAIOSFODNN7EXAMPLE",
            action="block",
        )

    def test_record_with_full_session(self):
        """All SessionContext fields stored in DB."""
        session = SessionContext(
            account_id="acct-1",
            api_key_hash="hash1234",
            session_id="sess-1",
            device_id="dev-1",
            source_ip="10.0.0.1",
            working_directory="/dev/repo",
            git_branch="main",
            os_platform="darwin",
            client_name="claude-code/1.0",
            raw_user_agent="claude-code/1.0.23",
            api_format="anthropic",
            sdk_name="claude-code",
            sdk_version="1.0.23",
            runtime="",
        )
        self.store.record_findings([self._finding()], provider="anthropic", model="opus", session=session)
        rows, total = self.store.get_findings_page()
        self.assertEqual(total, 1)
        r = rows[0]
        self.assertEqual(r["account_id"], "acct-1")
        self.assertEqual(r["session_id"], "sess-1")
        self.assertEqual(r["device_id"], "dev-1")
        self.assertEqual(r["source_ip"], "10.0.0.1")
        self.assertEqual(r["working_directory"], "/dev/repo")
        self.assertEqual(r["git_branch"], "main")
        self.assertEqual(r["os_platform"], "darwin")
        self.assertEqual(r["client_name"], "claude-code/1.0")
        self.assertEqual(r["api_key_hash"], "hash1234")
        self.assertEqual(r["raw_user_agent"], "claude-code/1.0.23")
        self.assertEqual(r["api_format"], "anthropic")
        self.assertEqual(r["sdk_name"], "claude-code")
        self.assertEqual(r["sdk_version"], "1.0.23")
        self.assertEqual(r["runtime"], "")

    def test_record_without_session(self):
        """None session stores empty strings."""
        self.store.record_findings([self._finding()], provider="anthropic")
        rows, _ = self.store.get_findings_page()
        self.assertEqual(rows[0]["session_id"], "")
        self.assertEqual(rows[0]["account_id"], "")

    def test_matched_value_never_stored(self):
        """matched_value must not be persisted in analytics DB."""
        self.store.record_findings([self._finding()], session=SessionContext(session_id="s1"))
        rows, _ = self.store.get_findings_page()
        self.assertNotIn("matched_value", rows[0])
        row_values = " ".join(str(v) for v in rows[0].values())
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", row_values)

    def test_filter_by_account_id(self):
        s1 = SessionContext(account_id="acct-a", session_id="s1")
        s2 = SessionContext(account_id="acct-b", session_id="s2")
        self.store.record_findings([self._finding()], session=s1)
        self.store.record_findings([self._finding()], session=s2)
        rows, total = self.store.get_findings_page(account_id="acct-a")
        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["account_id"], "acct-a")

    def test_get_sessions_includes_new_fields(self):
        session = SessionContext(
            session_id="sess-1",
            account_id="acct-1",
            device_id="dev-1",
            working_directory="/dev/repo",
            git_branch="main",
        )
        f1 = Finding(
            detector="secrets",
            type="aws_access_key",
            severity="critical",
            location="messages[0].content",
            value_preview="AKIA****",
            matched_value="AKIAIOSFODNN7EXAMPLE",
            action="block",
        )
        f2 = Finding(
            detector="secrets",
            type="github_token",
            severity="high",
            location="messages[1].content",
            value_preview="ghp_****",
            matched_value="ghp_EXAMPLE",
            action="block",
        )
        self.store.record_findings([f1], session=session)
        self.store.record_findings([f2], session=session)
        sessions = self.store.get_sessions()
        self.assertEqual(len(sessions), 1)
        s = sessions[0]
        self.assertEqual(s["session_id"], "sess-1")
        self.assertEqual(s["account_id"], "acct-1")
        self.assertEqual(s["device_id"], "dev-1")
        self.assertEqual(s["working_directory"], "/dev/repo")
        self.assertEqual(s["git_branch"], "main")
        self.assertEqual(s["finding_count"], 2)


# --- Pipeline passthrough ---


class TestPipelineSessionPassthrough(unittest.TestCase):
    def test_session_object_passed_to_store(self):
        from lumen_argus.extensions import ExtensionRegistry
        from lumen_argus.pipeline import ScannerPipeline

        store = MagicMock()
        ext = ExtensionRegistry()
        ext.set_analytics_store(store)
        pipeline = ScannerPipeline(default_action="alert", extensions=ext)
        session = SessionContext(session_id="fp:abc123", account_id="acct-1")
        body = b'{"messages":[{"role":"user","content":"AKIAIOSFODNN7EXAMPLE aws key"}]}'
        result = pipeline.scan(body, "anthropic", session=session)
        self.assertTrue(result.findings, "expected findings from known AWS key")
        store.record_findings.assert_called_once()
        call_kwargs = store.record_findings.call_args
        passed_session = call_kwargs.kwargs.get("session")
        self.assertEqual(passed_session.session_id, "fp:abc123")
        self.assertEqual(passed_session.account_id, "acct-1")

    def test_none_session_safe(self):
        from lumen_argus.extensions import ExtensionRegistry
        from lumen_argus.pipeline import ScannerPipeline

        store = MagicMock()
        ext = ExtensionRegistry()
        ext.set_analytics_store(store)
        pipeline = ScannerPipeline(default_action="alert", extensions=ext)
        body = b'{"messages":[{"role":"user","content":"AKIAIOSFODNN7EXAMPLE aws key"}]}'
        result = pipeline.scan(body, "anthropic")
        self.assertTrue(result.findings, "expected findings from known AWS key")
        call_kwargs = store.record_findings.call_args
        self.assertIsNone(call_kwargs.kwargs.get("session"))

    def test_session_passed_to_post_scan_hook(self):
        from lumen_argus.extensions import ExtensionRegistry
        from lumen_argus.pipeline import ScannerPipeline

        hook_calls = []

        def mock_hook(result, body, provider, **kwargs):
            hook_calls.append(kwargs)

        ext = ExtensionRegistry()
        ext.set_post_scan_hook(mock_hook)
        pipeline = ScannerPipeline(default_action="alert", extensions=ext)
        session = SessionContext(session_id="hdr:test")
        pipeline.scan(b'{"messages":[{"role":"user","content":"hello"}]}', "anthropic", session=session)
        self.assertEqual(len(hook_calls), 1)
        self.assertEqual(hook_calls[0]["session"].session_id, "hdr:test")


# --- Real Claude Code format integration test ---


class TestRealClaudeCodeFormat(unittest.TestCase):
    """Test with real Claude Code request format: system as list, user_id as JSON string."""

    # Real Claude Code environment block (from system prompt)
    _ENV_BLOCK = (
        "# Environment\n"
        "You have been invoked in the following environment:\n"
        " - Primary working directory: /Users/slim/dev/lumen-argus\n"
        "  - Is a git repository: true\n"
        " - Additional working directories:\n"
        "  - /Users/slim/dev/lumen-argus-spec\n"
        " - Platform: darwin\n"
        " - Shell: zsh\n"
        " - OS Version: Darwin 25.3.0\n"
        "\n"
        "Current branch: main\n"
        "\n"
        "Main branch (you will usually use this for PRs): main\n"
    )

    def test_full_extraction(self):
        """Extract all session fields from real Claude Code request format."""
        handler = _make_handler(client_address=("192.168.107.1", 54321))
        data = {
            "model": "claude-opus-4-6",
            "max_tokens": 16384,
            "system": [
                {"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."},
                {"type": "text", "text": self._ENV_BLOCK},
                {"type": "text", "text": "gitStatus: Current branch: main\n"},
            ],
            "metadata": {
                "user_id": (
                    '{"device_id":"dd7554a9ef88097c35dcf5652074dc8e0eb225854649ad0732cc00263b9ea250",'
                    '"account_uuid":"dbd6eafd-726c-4e2c-93ae-9132dae86705",'
                    '"session_id":"7ef7b337-2fed-492f-9a81-7c9d091eccd6"}'
                )
            },
            "messages": [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "Hi! How can I help?"},
            ],
        }
        headers = {
            "x-api-key": "sk-ant-api03-real-key-here",
            "user-agent": "claude-code/1.0.33 anthropic-ai/sdk-0.30.0 python/3.12.0",
            "anthropic-version": "2023-06-01",
        }
        ctx = handler._extract_session(data, "anthropic", headers)

        # Identity
        self.assertEqual(ctx.account_id, "dbd6eafd-726c-4e2c-93ae-9132dae86705")
        self.assertNotEqual(ctx.api_key_hash, "")
        self.assertEqual(len(ctx.api_key_hash), 16)

        # Session
        self.assertEqual(ctx.session_id, "7ef7b337-2fed-492f-9a81-7c9d091eccd6")
        self.assertEqual(ctx.device_id, "dd7554a9ef88097c35dcf5652074dc8e0eb225854649ad0732cc00263b9ea250")

        # Network
        self.assertEqual(ctx.source_ip, "192.168.107.1")

        # Context
        self.assertEqual(ctx.working_directory, "/Users/slim/dev/lumen-argus")
        self.assertEqual(ctx.git_branch, "main")
        self.assertEqual(ctx.os_platform, "darwin")

        # Client
        self.assertEqual(ctx.client_name, "claude_code")

    def test_no_metadata_falls_back_to_fingerprint(self):
        """Without metadata, session_id is derived fingerprint."""
        handler = _make_handler()
        data = {
            "system": [{"type": "text", "text": self._ENV_BLOCK}],
            "messages": [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "Hi!"},
            ],
        }
        ctx = handler._extract_session(data, "anthropic", {})
        self.assertTrue(ctx.session_id.startswith("fp:"))
        self.assertEqual(ctx.working_directory, "/Users/slim/dev/lumen-argus")
        self.assertEqual(ctx.git_branch, "main")
        self.assertEqual(ctx.os_platform, "darwin")


# --- Agent relay trusted headers ---


class TestTrustedAgentHeaders(unittest.TestCase):
    """X-Lumen-* headers from authenticated agent relay."""

    def test_trusted_agent_headers_populate_context(self):
        """Trusted agent relay headers override system prompt extraction."""
        data = {
            "system": "Primary working directory: /from-system-prompt\nCurrent branch: sp-branch\nPlatform: linux",
            "messages": [{"role": "user", "content": "hello"}],
        }
        headers = {
            "x-lumen-argus-working-dir": "/from-agent-relay",
            "x-lumen-argus-git-branch": "agent-branch",
            "x-lumen-argus-os-platform": "darwin",
            "x-lumen-argus-device-id": "mac_abc123",
            "x-lumen-argus-hostname": "macbook-pro",
            "x-lumen-argus-username": "slim",
        }
        ctx = _extract_session(data, "anthropic", headers, "10.0.0.1", trusted_agent=True)

        # Agent relay headers take priority over system prompt
        self.assertEqual(ctx.working_directory, "/from-agent-relay")
        self.assertEqual(ctx.git_branch, "agent-branch")
        self.assertEqual(ctx.os_platform, "darwin")
        self.assertEqual(ctx.device_id, "mac_abc123")
        self.assertEqual(ctx.hostname, "macbook-pro")
        self.assertEqual(ctx.username, "slim")

    def test_untrusted_ignores_lumen_headers(self):
        """Untrusted requests do NOT read X-Lumen-* headers."""
        data = {
            "system": "Primary working directory: /from-system-prompt\nPlatform: linux",
            "messages": [{"role": "user", "content": "hello"}],
        }
        headers = {
            "x-lumen-argus-working-dir": "/spoofed",
            "x-lumen-argus-hostname": "evil-host",
            "x-lumen-argus-username": "attacker",
        }
        ctx = _extract_session(data, "anthropic", headers, "10.0.0.1", trusted_agent=False)

        # System prompt extraction used instead
        self.assertEqual(ctx.working_directory, "/from-system-prompt")
        self.assertEqual(ctx.os_platform, "linux")
        # Agent-only fields remain empty
        self.assertEqual(ctx.hostname, "")
        self.assertEqual(ctx.username, "")

    def test_trusted_fallback_to_system_prompt(self):
        """Trusted agent with empty headers falls back to system prompt."""
        data = {
            "system": "Primary working directory: /from-sp\nCurrent branch: sp-main",
            "messages": [{"role": "user", "content": "hello"}],
        }
        headers = {
            # Agent headers empty
            "x-lumen-argus-working-dir": "",
            "x-lumen-argus-git-branch": "",
        }
        ctx = _extract_session(data, "anthropic", headers, "10.0.0.1", trusted_agent=True)

        # Falls back to system prompt
        self.assertEqual(ctx.working_directory, "/from-sp")
        self.assertEqual(ctx.git_branch, "sp-main")

    def test_trusted_partial_headers(self):
        """Trusted agent with some headers uses those, falls back for rest."""
        data = {
            "system": "Primary working directory: /from-sp\nCurrent branch: sp-branch\nPlatform: linux",
            "messages": [{"role": "user", "content": "hello"}],
        }
        headers = {
            "x-lumen-argus-working-dir": "/from-relay",
            # git_branch and os_platform not set — should fall back
        }
        ctx = _extract_session(data, "anthropic", headers, "10.0.0.1", trusted_agent=True)

        self.assertEqual(ctx.working_directory, "/from-relay")
        self.assertEqual(ctx.git_branch, "sp-branch")  # fallback
        self.assertEqual(ctx.os_platform, "linux")  # fallback

    def test_hostname_username_in_session_context(self):
        """New hostname/username fields exist on SessionContext."""
        ctx = SessionContext(hostname="my-machine", username="dev-user")
        self.assertEqual(ctx.hostname, "my-machine")
        self.assertEqual(ctx.username, "dev-user")

    def test_hostname_username_in_audit_entry(self):
        """New hostname/username fields included in AuditEntry serialization."""
        entry = AuditEntry(
            timestamp="t",
            request_id=1,
            provider="anthropic",
            model="opus",
            endpoint="/",
            action="alert",
            hostname="my-host",
            username="my-user",
        )
        d = entry.to_dict()
        self.assertEqual(d["hostname"], "my-host")
        self.assertEqual(d["username"], "my-user")

    def test_empty_hostname_username_omitted_from_audit(self):
        """Empty hostname/username not included in AuditEntry serialization."""
        entry = AuditEntry(
            timestamp="t",
            request_id=1,
            provider="anthropic",
            model="opus",
            endpoint="/",
            action="alert",
        )
        d = entry.to_dict()
        self.assertNotIn("hostname", d)
        self.assertNotIn("username", d)


class TestAnalyticsStoreHostnameUsername(StoreTestCase):
    """Test hostname and username storage in findings."""

    def _finding(self, ftype="aws_access_key", mv="AKIAIOSFODNN7EXAMPLE"):
        return Finding(
            detector="secrets",
            type=ftype,
            severity="critical",
            location="messages[0].content",
            value_preview="AKIA****",
            matched_value=mv,
            action="alert",
        )

    def test_record_with_hostname_username(self):
        session = SessionContext(
            session_id="sess-1",
            hostname="macbook-pro",
            username="slim",
            working_directory="/dev/proj",
        )
        self.store.record_findings([self._finding()], provider="anthropic", session=session)
        rows, total = self.store.get_findings_page()
        self.assertEqual(total, 1)
        r = rows[0]
        self.assertEqual(r["hostname"], "macbook-pro")
        self.assertEqual(r["username"], "slim")
        self.assertEqual(r["working_directory"], "/dev/proj")

    def test_filter_by_working_directory_substring(self):
        """working_directory filter uses LIKE (substring match)."""
        s1 = SessionContext(session_id="s1", working_directory="/Users/slim/dev/project-a")
        s2 = SessionContext(session_id="s2", working_directory="/Users/slim/dev/project-b")
        self.store.record_findings([self._finding(mv="key1")], session=s1)
        self.store.record_findings([self._finding(mv="key2")], session=s2)
        rows, total = self.store.get_findings_page(working_directory="project-a")
        self.assertEqual(total, 1)
        self.assertIn("project-a", rows[0]["working_directory"])

    def test_filter_by_hostname(self):
        s1 = SessionContext(session_id="s1", hostname="macbook")
        s2 = SessionContext(session_id="s2", hostname="linux-dev")
        self.store.record_findings([self._finding(mv="key1")], session=s1)
        self.store.record_findings([self._finding(mv="key2")], session=s2)
        rows, total = self.store.get_findings_page(hostname="macbook")
        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["hostname"], "macbook")

    def test_filter_by_username(self):
        s1 = SessionContext(session_id="s1", username="alice")
        s2 = SessionContext(session_id="s2", username="bob")
        self.store.record_findings([self._finding(mv="key1")], session=s1)
        self.store.record_findings([self._finding(mv="key2")], session=s2)
        rows, total = self.store.get_findings_page(username="bob")
        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["username"], "bob")

    def test_get_by_project(self):
        """get_by_project returns grouped summary with project name and agents."""
        s1 = SessionContext(
            session_id="s1",
            working_directory="/Users/slim/dev/project-a",
            client_name="claude_code",
        )
        s2 = SessionContext(
            session_id="s2",
            working_directory="/Users/slim/dev/project-b",
            client_name="cursor",
        )
        self.store.record_findings([self._finding(mv="key1")], session=s1)
        self.store.record_findings([self._finding(mv="key2")], session=s1)
        self.store.record_findings([self._finding(ftype="github_token", mv="key3")], session=s2)

        projects = self.store.get_by_project()
        self.assertEqual(len(projects), 2)

        # Sorted by finding_count desc
        proj_a = next(p for p in projects if "project-a" in p["working_directory"])
        proj_b = next(p for p in projects if "project-b" in p["working_directory"])

        self.assertEqual(proj_a["project_name"], "project-a")
        self.assertEqual(proj_a["finding_count"], 2)
        self.assertIn("claude_code", proj_a["agents"])

        self.assertEqual(proj_b["project_name"], "project-b")
        self.assertEqual(proj_b["finding_count"], 1)
        self.assertIn("cursor", proj_b["agents"])

    def test_get_by_project_empty(self):
        projects = self.store.get_by_project()
        self.assertEqual(projects, [])


class TestParseUserAgentMetadata(unittest.TestCase):
    """Test parse_user_agent_metadata — SDK, version, and runtime extraction."""

    def test_vercel_ai_sdk_anthropic(self):
        meta = parse_user_agent_metadata("ai-sdk/anthropic/3.0.64 ai-sdk/provider-utils/4.0.21 runtime/bun/1.3.11")
        self.assertEqual(meta["sdk_name"], "ai-sdk/anthropic")
        self.assertEqual(meta["sdk_version"], "3.0.64")
        self.assertEqual(meta["runtime"], "bun/1.3.11")

    def test_vercel_ai_sdk_openai(self):
        meta = parse_user_agent_metadata("ai-sdk/openai/3.0.48 ai-sdk/provider-utils/4.0.21 runtime/bun/1.3.11")
        self.assertEqual(meta["sdk_name"], "ai-sdk/openai")
        self.assertEqual(meta["sdk_version"], "3.0.48")
        self.assertEqual(meta["runtime"], "bun/1.3.11")

    def test_claude_code(self):
        meta = parse_user_agent_metadata("claude-code/1.0.23")
        self.assertEqual(meta["sdk_name"], "claude-code")
        self.assertEqual(meta["sdk_version"], "1.0.23")
        self.assertEqual(meta["runtime"], "")

    def test_aider(self):
        meta = parse_user_agent_metadata("aider/0.50.1")
        self.assertEqual(meta["sdk_name"], "aider")
        self.assertEqual(meta["sdk_version"], "0.50.1")

    def test_python_requests(self):
        meta = parse_user_agent_metadata("python-requests/2.31.0")
        self.assertEqual(meta["sdk_name"], "python-requests")
        self.assertEqual(meta["sdk_version"], "2.31.0")

    def test_node_runtime(self):
        meta = parse_user_agent_metadata("ai-sdk/openai/3.0.48 runtime/node/22.0.0")
        self.assertEqual(meta["runtime"], "node/22.0.0")

    def test_empty_ua(self):
        meta = parse_user_agent_metadata("")
        self.assertEqual(meta["sdk_name"], "")
        self.assertEqual(meta["sdk_version"], "")
        self.assertEqual(meta["runtime"], "")

    def test_browser_ua_parses_first_token(self):
        """Browser UAs are filtered upstream; parser just handles first token."""
        meta = parse_user_agent_metadata("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
        self.assertEqual(meta["sdk_name"], "Mozilla")
        self.assertEqual(meta["sdk_version"], "5.0")

    def test_no_version(self):
        meta = parse_user_agent_metadata("opencode")
        self.assertEqual(meta["sdk_name"], "opencode")
        self.assertEqual(meta["sdk_version"], "")

    def test_stainless_openai_sdk_headers(self):
        """Copilot CLI sends obfuscated UA but X-Stainless-* headers reveal the SDK."""
        meta = parse_user_agent_metadata(
            "O$t/JS 5.20.1",
            headers={
                "x-stainless-lang": "js",
                "x-stainless-package-version": "5.20.1",
                "x-stainless-runtime": "node",
                "x-stainless-runtime-version": "v24.11.1",
            },
        )
        self.assertEqual(meta["sdk_name"], "openai-js")
        self.assertEqual(meta["sdk_version"], "5.20.1")
        self.assertEqual(meta["runtime"], "node/v24.11.1")

    def test_stainless_python_sdk(self):
        """OpenAI Python SDK sends X-Stainless-Lang: python."""
        meta = parse_user_agent_metadata(
            "OpenAI/Python 1.50.0",
            headers={
                "x-stainless-lang": "python",
                "x-stainless-package-version": "1.50.0",
                "x-stainless-runtime": "CPython",
                "x-stainless-runtime-version": "3.12.0",
            },
        )
        self.assertEqual(meta["sdk_name"], "openai-python")
        self.assertEqual(meta["sdk_version"], "1.50.0")
        self.assertEqual(meta["runtime"], "CPython/3.12.0")

    def test_stainless_headers_without_ua(self):
        """Stainless headers enrich even when UA is empty."""
        meta = parse_user_agent_metadata(
            "unknown/1.0",
            headers={
                "x-stainless-lang": "js",
                "x-stainless-package-version": "5.20.1",
                "x-stainless-runtime": "node",
                "x-stainless-runtime-version": "v22.0.0",
            },
        )
        self.assertEqual(meta["sdk_name"], "openai-js")
        self.assertEqual(meta["sdk_version"], "5.20.1")
        self.assertEqual(meta["runtime"], "node/v22.0.0")

    def test_runtime_from_ua_not_overridden_by_stainless(self):
        """UA runtime token takes priority over X-Stainless-Runtime."""
        meta = parse_user_agent_metadata(
            "ai-sdk/openai/3.0.48 runtime/bun/1.3.11",
            headers={
                "x-stainless-runtime": "node",
                "x-stainless-runtime-version": "v22.0.0",
            },
        )
        # runtime/ token from UA wins
        self.assertEqual(meta["runtime"], "bun/1.3.11")


class TestClientTypeResolution(unittest.TestCase):
    """Test _resolve_client_type — interface type from headers or registry."""

    def test_opencode_explicit_cli(self):
        """OpenCode sends x-opencode-client: cli."""
        from lumen_argus.session import _resolve_client_type

        result = _resolve_client_type("opencode", {"x-opencode-client": "cli"})
        self.assertEqual(result, "cli")

    def test_opencode_explicit_app(self):
        """OpenCode desktop app sends x-opencode-client: app."""
        from lumen_argus.session import _resolve_client_type

        result = _resolve_client_type("opencode", {"x-opencode-client": "app"})
        self.assertEqual(result, "app")

    def test_claude_code_derived_cli(self):
        """Claude Code has category=cli in registry, derived to cli."""
        from lumen_argus.session import _resolve_client_type

        result = _resolve_client_type("claude_code", {})
        self.assertEqual(result, "cli")

    def test_cursor_derived_ide(self):
        """Cursor has category=ide in registry, derived to ide."""
        from lumen_argus.session import _resolve_client_type

        result = _resolve_client_type("cursor", {})
        self.assertEqual(result, "ide")

    def test_unknown_client_empty(self):
        """Unknown client returns empty string."""
        from lumen_argus.session import _resolve_client_type

        result = _resolve_client_type("unknown-tool", {})
        self.assertEqual(result, "")

    def test_explicit_header_beats_registry(self):
        """x-opencode-client header takes priority over registry category."""
        from lumen_argus.session import _resolve_client_type

        # opencode is category=cli, but header says "app"
        result = _resolve_client_type("opencode", {"x-opencode-client": "app"})
        self.assertEqual(result, "app")


class TestOpenCodeEndToEnd(unittest.TestCase):
    """End-to-end tests for OpenCode request metadata through the full pipeline.

    Validates that OpenCode's actual User-Agent strings, system prompt format,
    and session context are correctly parsed and stored.
    """

    def test_opencode_anthropic_adapter_metadata(self):
        """OpenCode using Anthropic SDK adapter (e.g., MiniMax via Zen)."""
        ua = "ai-sdk/anthropic/3.0.64 ai-sdk/provider-utils/4.0.21 runtime/bun/1.3.11"
        meta = parse_user_agent_metadata(ua)
        self.assertEqual(meta["sdk_name"], "ai-sdk/anthropic")
        self.assertEqual(meta["sdk_version"], "3.0.64")
        self.assertEqual(meta["runtime"], "bun/1.3.11")

        # Client identification via x-session-affinity
        from lumen_argus_core.clients import identify_client

        cid, name, _, raw = identify_client(ua, headers={"x-session-affinity": "sess-1"})
        self.assertEqual(cid, "opencode")
        self.assertEqual(name, "OpenCode")
        self.assertEqual(raw, "ai-sdk/anthropic/3.0.64")

    def test_opencode_openai_adapter_metadata(self):
        """OpenCode using OpenAI SDK adapter (e.g., GPT-5 via Zen)."""
        ua = "ai-sdk/openai/3.0.48 ai-sdk/provider-utils/4.0.21 runtime/bun/1.3.11"
        meta = parse_user_agent_metadata(ua)
        self.assertEqual(meta["sdk_name"], "ai-sdk/openai")
        self.assertEqual(meta["sdk_version"], "3.0.48")
        self.assertEqual(meta["runtime"], "bun/1.3.11")

        from lumen_argus_core.clients import identify_client

        cid, _, _, _ = identify_client(ua, headers={"x-session-affinity": "sess-2"})
        self.assertEqual(cid, "opencode")

    def test_opencode_working_directory_anthropic_format(self):
        """OpenCode system prompt in Anthropic format extracts working directory."""
        system = (
            "You are powered by the model named minimax-m2.5-free.\n"
            "<env>\n"
            "  Working directory: /Users/dev/myproject\n"
            "  Workspace root folder: /Users/dev/myproject\n"
            "  Is directory a git repo: yes\n"
            "  Platform: darwin\n"
            "</env>"
        )
        data = {"system": [{"type": "text", "text": system}], "messages": []}
        wd = _extract_working_directory(data, "anthropic")
        self.assertEqual(wd, "/Users/dev/myproject")

    def test_opencode_working_directory_openai_format(self):
        """OpenCode system prompt in OpenAI format extracts working directory."""
        system = "<env>\n  Working directory: /home/user/project\n  Platform: linux\n</env>"
        data = {"messages": [{"role": "system", "content": system}]}
        wd = _extract_working_directory(data, "openai")
        self.assertEqual(wd, "/home/user/project")

    def test_opencode_platform_extracted(self):
        """OpenCode's Platform: field in <env> block is extracted."""
        system = "<env>\n  Working directory: /tmp\n  Platform: darwin\n</env>"
        data = {"system": system, "messages": []}
        platform = _extract_system_field(data, "anthropic", _OS_PLATFORM_PATTERNS)
        self.assertEqual(platform, "darwin")

    def test_opencode_full_session_context(self):
        """Verify all metadata fields populate correctly for an OpenCode request."""
        session = SessionContext(
            client_name="opencode",
            raw_user_agent="ai-sdk/anthropic/3.0.64 ai-sdk/provider-utils/4.0.21 runtime/bun/1.3.11",
            api_format="anthropic",
            sdk_name="ai-sdk/anthropic",
            sdk_version="3.0.64",
            runtime="bun/1.3.11",
            working_directory="/Users/dev/project",
            os_platform="darwin",
        )
        # Verify all fields are set
        self.assertEqual(session.client_name, "opencode")
        self.assertEqual(session.sdk_name, "ai-sdk/anthropic")
        self.assertEqual(session.sdk_version, "3.0.64")
        self.assertEqual(session.runtime, "bun/1.3.11")
        self.assertEqual(session.api_format, "anthropic")

    def test_opencode_db_round_trip(self):
        """OpenCode metadata survives DB storage and retrieval."""
        from tests.helpers import make_store

        store, _ = make_store()
        session = SessionContext(
            client_name="opencode",
            client_type="cli",
            raw_user_agent="ai-sdk/openai/3.0.48 runtime/bun/1.3.11",
            api_format="openai",
            sdk_name="ai-sdk/openai",
            sdk_version="3.0.48",
            runtime="bun/1.3.11",
            working_directory="/Users/dev/zen-test",
        )
        from lumen_argus.models import Finding

        f = Finding(
            detector="secrets",
            type="aws_access_key",
            severity="critical",
            location="messages[0].content",
            matched_value="AKIAIOSFODNN7EXAMPLE",
            value_preview="AKIA****",
            action="alert",
        )
        store.record_findings([f], provider="opencode", model="minimax-m2.5-free", session=session)
        rows, total = store.get_findings_page()
        self.assertEqual(total, 1)
        r = rows[0]
        self.assertEqual(r["provider"], "opencode")
        self.assertEqual(r["model"], "minimax-m2.5-free")
        self.assertEqual(r["client_name"], "opencode")
        self.assertEqual(r["client_type"], "cli")
        self.assertEqual(r["raw_user_agent"], "ai-sdk/openai/3.0.48 runtime/bun/1.3.11")
        self.assertEqual(r["api_format"], "openai")
        self.assertEqual(r["sdk_name"], "ai-sdk/openai")
        self.assertEqual(r["sdk_version"], "3.0.48")
        self.assertEqual(r["runtime"], "bun/1.3.11")
        self.assertEqual(r["working_directory"], "/Users/dev/zen-test")

    def test_opencode_audit_entry(self):
        """OpenCode metadata appears in audit JSONL output."""
        from lumen_argus.models import AuditEntry

        entry = AuditEntry(
            timestamp="2026-04-08T07:41:35Z",
            request_id=1,
            provider="opencode",
            model="minimax-m2.5-free",
            endpoint="/zen/v1/messages",
            action="alert",
            raw_user_agent="ai-sdk/anthropic/3.0.64 runtime/bun/1.3.11",
            api_format="anthropic",
            sdk_name="ai-sdk/anthropic",
            sdk_version="3.0.64",
            runtime="bun/1.3.11",
            client_name="opencode",
        )
        d = entry.to_dict()
        self.assertEqual(d["provider"], "opencode")
        self.assertEqual(d["raw_user_agent"], "ai-sdk/anthropic/3.0.64 runtime/bun/1.3.11")
        self.assertEqual(d["sdk_name"], "ai-sdk/anthropic")
        self.assertEqual(d["sdk_version"], "3.0.64")
        self.assertEqual(d["runtime"], "bun/1.3.11")
        self.assertEqual(d["api_format"], "anthropic")
        self.assertEqual(d["client_name"], "opencode")


if __name__ == "__main__":
    unittest.main()
