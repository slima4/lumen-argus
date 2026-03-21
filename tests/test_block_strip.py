"""Tests for block action history stripping."""

import json
import unittest

from lumen_argus.actions import try_strip_blocked_history
from lumen_argus.models import Finding


_FAKE_SECRET = "FAKE_SECRET_VALUE_FOR_TESTING"


def _make_finding(location="messages[0].content", ftype="stripe_secret_key"):
    return Finding(
        detector="secrets",
        type=ftype,
        severity="critical",
        location=location,
        value_preview="sk_l****",
        matched_value=_FAKE_SECRET,
    )


class TestTryStripBlockedHistory(unittest.TestCase):
    """Unit tests for try_strip_blocked_history."""

    def test_finding_in_last_user_message_returns_none(self):
        """New sensitive data in the latest message — must block, not strip."""
        req_data = {
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "My key: FAKE_SECRET_FOR_TEST"},
            ],
        }
        findings = [_make_finding("messages[0].content")]
        result = try_strip_blocked_history(req_data, findings)
        self.assertIsNone(result)

    def test_finding_in_history_strips_message(self):
        """Finding in earlier message — strip it and return cleaned body."""
        req_data = {
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "My key: FAKE_SECRET_FOR_TEST"},
                {"role": "assistant", "content": "Error: blocked."},
                {"role": "user", "content": "test"},
            ],
        }
        findings = [_make_finding("messages[0].content")]
        result = try_strip_blocked_history(req_data, findings)
        self.assertIsNotNone(result)

        cleaned = json.loads(result)
        # Should have stripped messages[0] (user with secret) and messages[1] (assistant reply)
        self.assertEqual(len(cleaned["messages"]), 1)
        self.assertEqual(cleaned["messages"][0]["content"], "test")

    def test_strips_assistant_reply_after_blocked_user_message(self):
        """Stripping a user message also strips the following assistant reply."""
        req_data = {
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "My key: sk_live_xxx"},
                {"role": "assistant", "content": "I see your key."},
                {"role": "user", "content": "help me"},
            ],
        }
        findings = [_make_finding("messages[0].content")]
        result = try_strip_blocked_history(req_data, findings)
        cleaned = json.loads(result)
        self.assertEqual(len(cleaned["messages"]), 1)
        self.assertEqual(cleaned["messages"][0]["role"], "user")
        self.assertEqual(cleaned["messages"][0]["content"], "help me")

    def test_does_not_strip_assistant_if_not_following(self):
        """Only strip assistant reply immediately after the blocked user message."""
        req_data = {
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "My key: sk_live_xxx"},
                {"role": "user", "content": "another question"},
                {"role": "assistant", "content": "Sure."},
                {"role": "user", "content": "test"},
            ],
        }
        findings = [_make_finding("messages[0].content")]
        result = try_strip_blocked_history(req_data, findings)
        cleaned = json.loads(result)
        # messages[0] stripped, messages[1] stays (user, not assistant after blocked)
        self.assertEqual(len(cleaned["messages"]), 3)
        self.assertEqual(cleaned["messages"][0]["content"], "another question")

    def test_multiple_findings_in_history(self):
        """Multiple blocked messages in history — all stripped."""
        req_data = {
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "key: sk_live_xxx"},
                {"role": "assistant", "content": "blocked"},
                {"role": "user", "content": "key: AKIAIOSFODNN7EXAMPLE"},
                {"role": "assistant", "content": "blocked again"},
                {"role": "user", "content": "clean message"},
            ],
        }
        findings = [
            _make_finding("messages[0].content", "stripe_secret_key"),
            _make_finding("messages[2].content", "aws_access_key"),
        ]
        result = try_strip_blocked_history(req_data, findings)
        cleaned = json.loads(result)
        self.assertEqual(len(cleaned["messages"]), 1)
        self.assertEqual(cleaned["messages"][0]["content"], "clean message")

    def test_finding_in_both_history_and_last_message_blocks(self):
        """If latest message also has sensitive data, must block (not strip)."""
        req_data = {
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "key: sk_live_xxx"},
                {"role": "user", "content": "another key: sk_live_yyy"},
            ],
        }
        findings = [
            _make_finding("messages[0].content"),
            _make_finding("messages[1].content"),
        ]
        result = try_strip_blocked_history(req_data, findings)
        self.assertIsNone(result)

    def test_preserves_model_and_other_fields(self):
        """Stripping only affects messages, other request fields preserved."""
        req_data = {
            "model": "claude-opus-4-6",
            "stream": True,
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": "key: sk_live_xxx"},
                {"role": "assistant", "content": "blocked"},
                {"role": "user", "content": "test"},
            ],
        }
        findings = [_make_finding("messages[0].content")]
        result = try_strip_blocked_history(req_data, findings)
        cleaned = json.loads(result)
        self.assertEqual(cleaned["model"], "claude-opus-4-6")
        self.assertTrue(cleaned["stream"])
        self.assertEqual(cleaned["max_tokens"], 1024)

    def test_empty_messages_after_strip_returns_none(self):
        """If stripping removes all messages, return None (block instead)."""
        req_data = {
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "key: sk_live_xxx"},
            ],
        }
        # Finding in messages[0], which is also the last user message → blocks
        findings = [_make_finding("messages[0].content")]
        result = try_strip_blocked_history(req_data, findings)
        self.assertIsNone(result)

    def test_none_req_data_returns_none(self):
        result = try_strip_blocked_history(None, [_make_finding()])
        self.assertIsNone(result)

    def test_no_messages_key_returns_none(self):
        result = try_strip_blocked_history({"model": "test"}, [_make_finding()])
        self.assertIsNone(result)

    def test_finding_without_message_index_returns_none(self):
        """Finding with non-standard location — can't determine index, block."""
        req_data = {
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "test"},
            ],
        }
        findings = [_make_finding("system_prompt")]
        result = try_strip_blocked_history(req_data, findings)
        self.assertIsNone(result)

    # --- Content-block-level stripping (Claude Code packs everything in messages[0]) ---

    def test_content_block_finding_in_history_strips_block(self):
        """Claude Code style: single message with multiple content blocks.
        Finding in earlier block, user's new input in last block → strip block."""
        req_data = {
            "model": "claude-opus-4-6",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "system context here"},
                        {"type": "text", "text": "previous message with sk_live_xxx"},
                        {"type": "text", "text": "assistant reply"},
                        {"type": "text", "text": "test"},
                    ],
                }
            ],
        }
        findings = [_make_finding("messages[0].content[1]")]
        result = try_strip_blocked_history(req_data, findings)
        self.assertIsNotNone(result)

        cleaned = json.loads(result)
        content = cleaned["messages"][0]["content"]
        self.assertEqual(len(content), 3)
        # Block 1 (with secret) stripped, others preserved
        self.assertEqual(content[0]["text"], "system context here")
        self.assertEqual(content[1]["text"], "assistant reply")
        self.assertEqual(content[2]["text"], "test")

    def test_content_block_finding_in_last_block_blocks(self):
        """Finding in the LAST content block (user just typed it) → must block."""
        req_data = {
            "model": "claude-opus-4-6",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "clean context"},
                        {"type": "text", "text": "sk_live_xxx"},
                    ],
                }
            ],
        }
        findings = [_make_finding("messages[0].content[1]")]
        result = try_strip_blocked_history(req_data, findings)
        self.assertIsNone(result)

    def test_content_block_multiple_findings_stripped(self):
        """Multiple content blocks with findings — all stripped."""
        req_data = {
            "model": "claude-opus-4-6",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "context"},
                        {"type": "text", "text": "secret1: sk_live_xxx"},
                        {"type": "text", "text": "secret2: AKIA_xxx"},
                        {"type": "text", "text": "clean follow-up"},
                    ],
                }
            ],
        }
        findings = [
            _make_finding("messages[0].content[1]", "stripe_secret_key"),
            _make_finding("messages[0].content[2]", "aws_access_key"),
        ]
        result = try_strip_blocked_history(req_data, findings)
        self.assertIsNotNone(result)

        cleaned = json.loads(result)
        content = cleaned["messages"][0]["content"]
        self.assertEqual(len(content), 2)
        self.assertEqual(content[0]["text"], "context")
        self.assertEqual(content[1]["text"], "clean follow-up")

    def test_content_block_string_content_blocks(self):
        """String content (not array) in last message — can't strip blocks, block."""
        req_data = {
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "sk_live_xxx and test"},
            ],
        }
        findings = [_make_finding("messages[0].content")]
        result = try_strip_blocked_history(req_data, findings)
        self.assertIsNone(result)

    def test_content_block_all_blocks_stripped_returns_none(self):
        """If stripping removes all content blocks, return None."""
        req_data = {
            "model": "claude-opus-4-6",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "sk_live_xxx"},
                    ],
                }
            ],
        }
        findings = [_make_finding("messages[0].content[0]")]
        result = try_strip_blocked_history(req_data, findings)
        self.assertIsNone(result)

    def test_content_block_out_of_range_index_blocks(self):
        """Out-of-range block index must block, not silently skip."""
        req_data = {
            "model": "claude-opus-4-6",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "clean context"},
                        {"type": "text", "text": "user input"},
                    ],
                }
            ],
        }
        # Block index 999 doesn't exist in the 2-element content array
        findings = [_make_finding("messages[0].content[999]")]
        result = try_strip_blocked_history(req_data, findings)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
