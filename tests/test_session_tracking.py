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
import unittest
from unittest.mock import MagicMock

from lumen_argus_core.clients import identify_client

from lumen_argus.models import AuditEntry, Finding, SessionContext
from lumen_argus.session import (
    _GIT_BRANCH_PATTERNS,
    _OS_PLATFORM_PATTERNS,
    _derive_session_fingerprint,
    _extract_system_field,
    _extract_working_directory,
    _get_system_text,
)
from lumen_argus.session import (
    extract_session as _extract_session,
)
from tests.helpers import StoreTestCase


class _HandlerShim:
    """Thin shim: adapts module-level _extract_session to handler.method() pattern."""

    def __init__(self, client_address=("127.0.0.1", 54321)):
        self.client_address = client_address

    def _extract_session(self, data, provider, headers):
        return _extract_session(data, provider, headers, self.client_address[0])


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
        ctx = handler._extract_session({}, "anthropic", {"x-api-key": "sk-ant-test123"})
        expected = hashlib.sha256(b"sk-ant-test123").hexdigest()[:16]
        self.assertEqual(ctx.api_key_hash, expected)
        self.assertEqual(len(ctx.api_key_hash), 16)

    def test_bearer_token_stripped(self):
        handler = _make_handler()
        ctx = handler._extract_session({}, "anthropic", {"authorization": "Bearer sk-test"})
        expected = hashlib.sha256(b"sk-test").hexdigest()[:16]
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


if __name__ == "__main__":
    unittest.main()
