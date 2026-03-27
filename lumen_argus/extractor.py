"""Request body field extraction for scanning.

Knows how to extract scannable text from Anthropic, OpenAI, and Gemini
API request formats.
"""

import json
from typing import Any

from lumen_argus.models import ScanField


class RequestExtractor:
    """Extracts scannable text fields from API request bodies."""

    def extract(self, body: bytes, provider: str) -> list[ScanField]:
        """Parse request JSON and extract all text fields to scan.

        Args:
            body: Raw request body bytes.
            provider: Provider name ("anthropic", "openai", "gemini", "unknown").

        Returns:
            List of ScanField objects containing text to scan.
        """
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []

        if not isinstance(data, dict):
            return []

        dispatch = {
            "anthropic": self._extract_anthropic,
            "openai": self._extract_openai,
            "gemini": self._extract_gemini,
        }
        extractor = dispatch.get(provider, self._extract_generic)
        return extractor(data)

    def _extract_anthropic(self, data: dict[str, Any]) -> list[ScanField]:
        """Extract from Anthropic Messages API format."""
        fields: list[ScanField] = []

        # System prompt
        system = data.get("system")
        if isinstance(system, str) and system:
            fields.append(ScanField(path="system", text=system))
        elif isinstance(system, list):
            for i, block in enumerate(system):
                if isinstance(block, dict):
                    text = block.get("text", "")
                    if text:
                        fields.append(ScanField(path="system[%d]" % i, text=text))

        # Messages
        messages = data.get("messages", [])
        for i, msg in enumerate(messages):
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if isinstance(content, str) and content:
                fields.append(
                    ScanField(
                        path="messages[%d].content" % i,
                        text=content,
                    )
                )
            elif isinstance(content, list):
                for j, block in enumerate(content):
                    if not isinstance(block, dict):
                        continue
                    block_type = block.get("type", "")

                    if block_type == "text":
                        text = block.get("text", "")
                        if text:
                            fields.append(
                                ScanField(
                                    path="messages[%d].content[%d]" % (i, j),
                                    text=text,
                                )
                            )
                    elif block_type == "tool_result":
                        self._extract_tool_result(block, "messages[%d].content[%d]" % (i, j), fields)

        return fields

    def _extract_tool_result(self, block: dict[str, Any], base_path: str, fields: list[ScanField]) -> None:
        """Extract text from tool_result content blocks."""
        content = block.get("content")
        source_file = ""

        # Try to find a filename in the tool input context
        tool_input = block.get("input", {})
        if isinstance(tool_input, dict):
            source_file = (
                tool_input.get("file_path", "") or tool_input.get("path", "") or tool_input.get("filename", "")
            )

        if isinstance(content, str) and content:
            fields.append(
                ScanField(
                    path=base_path,
                    text=content,
                    source_filename=source_file,
                )
            )
        elif isinstance(content, list):
            for k, sub_block in enumerate(content):
                if isinstance(sub_block, dict) and sub_block.get("type") == "text":
                    text = sub_block.get("text", "")
                    if text:
                        fields.append(
                            ScanField(
                                path="%s.content[%d]" % (base_path, k),
                                text=text,
                                source_filename=source_file,
                            )
                        )

    def _extract_openai(self, data: dict[str, Any]) -> list[ScanField]:
        """Extract from OpenAI Chat Completions API format."""
        fields: list[ScanField] = []

        messages = data.get("messages", [])
        for i, msg in enumerate(messages):
            if not isinstance(msg, dict):
                continue

            content = msg.get("content")
            role = msg.get("role", "")

            if role != "tool":
                # General content extraction (skip tool role — handled below)
                if isinstance(content, str) and content:
                    fields.append(
                        ScanField(
                            path="messages[%d].content" % i,
                            text=content,
                        )
                    )
                elif isinstance(content, list):
                    for j, part in enumerate(content):
                        if isinstance(part, dict) and part.get("type") == "text":
                            text = part.get("text", "")
                            if text:
                                fields.append(
                                    ScanField(
                                        path="messages[%d].content[%d]" % (i, j),
                                        text=text,
                                    )
                                )
            else:
                # Tool/function call results
                tool_content = msg.get("content", "")
                if isinstance(tool_content, str) and tool_content:
                    fields.append(
                        ScanField(
                            path="messages[%d].content" % i,
                            text=tool_content,
                        )
                    )

            # Tool calls from assistant messages (#9)
            if role == "assistant":
                tool_calls = msg.get("tool_calls", [])
                if isinstance(tool_calls, list):
                    for k, tc in enumerate(tool_calls):
                        if not isinstance(tc, dict):
                            continue
                        func = tc.get("function", {})
                        if not isinstance(func, dict):
                            continue
                        args_str = func.get("arguments", "")
                        if not isinstance(args_str, str) or not args_str:
                            continue
                        try:
                            args_data = json.loads(args_str)
                            if isinstance(args_data, dict):
                                for arg_key, arg_val in args_data.items():
                                    if isinstance(arg_val, str) and arg_val:
                                        fields.append(
                                            ScanField(
                                                path="messages[%d].tool_calls[%d].function.arguments.%s"
                                                % (i, k, arg_key),
                                                text=arg_val,
                                            )
                                        )
                        except (json.JSONDecodeError, ValueError):
                            if len(args_str) > 20:
                                fields.append(
                                    ScanField(
                                        path="messages[%d].tool_calls[%d].function.arguments" % (i, k),
                                        text=args_str,
                                    )
                                )

        return fields

    def _extract_gemini(self, data: dict[str, Any]) -> list[ScanField]:
        """Extract from Gemini generateContent API format."""
        fields: list[ScanField] = []

        # System instruction
        sys_instr = data.get("systemInstruction", {})
        if isinstance(sys_instr, dict):
            parts = sys_instr.get("parts", [])
            for i, part in enumerate(parts):
                if isinstance(part, dict):
                    text = part.get("text", "")
                    if text:
                        fields.append(
                            ScanField(
                                path="systemInstruction.parts[%d]" % i,
                                text=text,
                            )
                        )

        # Contents
        contents = data.get("contents", [])
        for i, content in enumerate(contents):
            if not isinstance(content, dict):
                continue
            parts = content.get("parts", [])
            for j, part in enumerate(parts):
                if not isinstance(part, dict):
                    continue
                text = part.get("text", "")
                if text:
                    fields.append(
                        ScanField(
                            path="contents[%d].parts[%d]" % (i, j),
                            text=text,
                        )
                    )
                # Function response (#10)
                func_resp = part.get("functionResponse", {})
                if isinstance(func_resp, dict):
                    resp_data = func_resp.get("response", {})
                    if isinstance(resp_data, dict):
                        self._walk_nested(
                            resp_data,
                            "contents[%d].parts[%d].functionResponse.response" % (i, j),
                            fields,
                        )
                # Function call arguments (#10)
                func_call = part.get("functionCall", {})
                if isinstance(func_call, dict):
                    args = func_call.get("args", {})
                    if isinstance(args, dict):
                        self._walk_nested(
                            args,
                            "contents[%d].parts[%d].functionCall.args" % (i, j),
                            fields,
                        )

        return fields

    def _walk_nested(self, obj: object, path: str, fields: list[ScanField]) -> None:
        """Recursively extract string values from nested dicts/lists."""
        if isinstance(obj, str) and obj:
            fields.append(ScanField(path=path, text=obj))
        elif isinstance(obj, dict):
            for k, v in obj.items():
                self._walk_nested(v, "%s.%s" % (path, k), fields)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                self._walk_nested(v, "%s[%d]" % (path, i), fields)

    def _extract_generic(self, data: dict[str, Any]) -> list[ScanField]:
        """Fallback: recursively extract all string values > 20 chars."""
        fields: list[ScanField] = []
        self._walk(data, "", fields)
        return fields

    def _walk(self, obj: object, path: str, fields: list[ScanField]) -> None:
        """Recursively walk JSON and collect long string values."""
        if isinstance(obj, str):
            if len(obj) > 20:
                fields.append(ScanField(path=path, text=obj))
        elif isinstance(obj, dict):
            for k, v in obj.items():
                child_path = "%s.%s" % (path, k) if path else k
                self._walk(v, child_path, fields)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                self._walk(v, "%s[%d]" % (path, i), fields)
