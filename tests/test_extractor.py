"""Tests for the request body extractor."""

import json
import unittest

from lumen_argus.extractor import RequestExtractor


class TestAnthropicExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = RequestExtractor()

    def test_system_string(self):
        body = json.dumps({
            "model": "claude-opus-4-6",
            "system": "You are a helpful assistant.",
            "messages": [],
        }).encode()
        fields = self.extractor.extract(body, "anthropic")
        paths = [f.path for f in fields]
        self.assertIn("system", paths)

    def test_system_content_blocks(self):
        body = json.dumps({
            "model": "claude-opus-4-6",
            "system": [{"type": "text", "text": "System prompt here."}],
            "messages": [],
        }).encode()
        fields = self.extractor.extract(body, "anthropic")
        paths = [f.path for f in fields]
        self.assertIn("system[0]", paths)

    def test_message_string_content(self):
        body = json.dumps({
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "Hello, world!"},
            ],
        }).encode()
        fields = self.extractor.extract(body, "anthropic")
        self.assertEqual(len(fields), 1)
        self.assertEqual(fields[0].text, "Hello, world!")

    def test_message_content_blocks(self):
        body = json.dumps({
            "model": "claude-opus-4-6",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "First block"},
                        {"type": "text", "text": "Second block"},
                    ],
                },
            ],
        }).encode()
        fields = self.extractor.extract(body, "anthropic")
        self.assertEqual(len(fields), 2)

    def test_tool_result_content(self):
        body = json.dumps({
            "model": "claude-opus-4-6",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "content": "File contents: SECRET=abc123",
                            "input": {"file_path": "/app/.env"},
                        },
                    ],
                },
            ],
        }).encode()
        fields = self.extractor.extract(body, "anthropic")
        self.assertEqual(len(fields), 1)
        self.assertEqual(fields[0].source_filename, "/app/.env")
        self.assertIn("SECRET=abc123", fields[0].text)

    def test_multiple_messages(self):
        body = json.dumps({
            "model": "claude-opus-4-6",
            "messages": [
                {"role": "user", "content": "Message 1"},
                {"role": "assistant", "content": "Response 1"},
                {"role": "user", "content": "Message 2"},
            ],
        }).encode()
        fields = self.extractor.extract(body, "anthropic")
        self.assertEqual(len(fields), 3)


class TestOpenAIExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = RequestExtractor()

    def test_chat_completion(self):
        body = json.dumps({
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Hello!"},
            ],
        }).encode()
        fields = self.extractor.extract(body, "openai")
        self.assertEqual(len(fields), 2)

    def test_tool_result(self):
        body = json.dumps({
            "model": "gpt-4",
            "messages": [
                {"role": "tool", "content": "Tool output data here."},
            ],
        }).encode()
        fields = self.extractor.extract(body, "openai")
        texts = [f.text for f in fields]
        self.assertTrue(any("Tool output" in t for t in texts))

    def test_tool_calls_extraction(self):
        """#9: Extract function arguments from assistant tool_calls."""
        body = json.dumps({
            "model": "gpt-4",
            "messages": [
                {"role": "assistant", "content": None, "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {
                        "name": "write_file",
                        "arguments": '{"path": "/tmp/test.txt", "content": "secret data here"}'
                    }}
                ]}
            ],
        }).encode()
        fields = self.extractor.extract(body, "openai")
        texts = [f.text for f in fields]
        self.assertTrue(any("secret data here" in t for t in texts))
        paths = [f.path for f in fields]
        self.assertTrue(any("tool_calls" in p for p in paths))

    def test_tool_calls_non_json_arguments(self):
        """#9: Non-JSON arguments longer than 20 chars are extracted as-is."""
        body = json.dumps({
            "model": "gpt-4",
            "messages": [
                {"role": "assistant", "content": None, "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {
                        "name": "run",
                        "arguments": "this is not json but longer than twenty chars"
                    }}
                ]}
            ],
        }).encode()
        fields = self.extractor.extract(body, "openai")
        texts = [f.text for f in fields]
        self.assertTrue(any("this is not json" in t for t in texts))


class TestGeminiExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = RequestExtractor()

    def test_generate_content(self):
        body = json.dumps({
            "contents": [
                {"parts": [{"text": "Hello Gemini!"}]},
            ],
            "systemInstruction": {
                "parts": [{"text": "Be helpful."}],
            },
        }).encode()
        fields = self.extractor.extract(body, "gemini")
        self.assertEqual(len(fields), 2)
        paths = [f.path for f in fields]
        self.assertIn("systemInstruction.parts[0]", paths)
        self.assertIn("contents[0].parts[0]", paths)

    def test_function_response(self):
        """#10: Extract Gemini functionResponse data."""
        body = json.dumps({
            "contents": [{
                "role": "function",
                "parts": [{"functionResponse": {
                    "name": "get_secret",
                    "response": {"result": "sensitive_value_here"}
                }}]
            }]
        }).encode()
        fields = self.extractor.extract(body, "gemini")
        texts = [f.text for f in fields]
        self.assertIn("sensitive_value_here", texts)

    def test_function_call_args(self):
        """#10: Extract Gemini functionCall arguments."""
        body = json.dumps({
            "contents": [{
                "role": "model",
                "parts": [{"functionCall": {
                    "name": "store_data",
                    "args": {"data": "secret_content"}
                }}]
            }]
        }).encode()
        fields = self.extractor.extract(body, "gemini")
        texts = [f.text for f in fields]
        self.assertIn("secret_content", texts)


class TestGenericExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = RequestExtractor()

    def test_generic_extracts_long_strings(self):
        body = json.dumps({
            "data": "This is a string longer than 20 characters for testing",
            "short": "tiny",
        }).encode()
        fields = self.extractor.extract(body, "unknown")
        texts = [f.text for f in fields]
        self.assertEqual(len(texts), 1)
        self.assertIn("This is a string longer than 20 characters for testing", texts)

    def test_invalid_json_returns_empty(self):
        fields = self.extractor.extract(b"not json", "anthropic")
        self.assertEqual(len(fields), 0)

    def test_empty_body_returns_empty(self):
        fields = self.extractor.extract(b"", "anthropic")
        self.assertEqual(len(fields), 0)


if __name__ == "__main__":
    unittest.main()
