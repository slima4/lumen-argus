"""Session context extraction from HTTP request headers and body metadata.

Extracts identity, environment, and project context from proxied requests
to enable security investigation (WHO leaked, WHICH conversation, WHERE from).

Moved from async_proxy.py to isolate session extraction logic from proxy transport.
"""

import hashlib
import json
import logging
import re
from typing import Any

from lumen_argus_core.clients import identify_client

from lumen_argus.models import SessionContext

log = logging.getLogger("argus.session")

# ---------------------------------------------------------------------------
# Compiled patterns for system prompt field extraction
# ---------------------------------------------------------------------------

_WORKDIR_PATTERNS = [
    re.compile(r"Primary working directory:\s*(.+?)(?:\n|$)"),
    re.compile(r"You are working in:\s*(.+?)(?:\n|$)"),
    re.compile(r"(?:cwd|working_directory):\s*(.+?)(?:\n|$)", re.IGNORECASE),
]
_GIT_BRANCH_PATTERNS = [
    re.compile(r"Current branch:\s*(.+?)(?:\n|$)"),
    re.compile(r"(?:git branch|branch):\s*(.+?)(?:\n|$)", re.IGNORECASE),
]
_OS_PLATFORM_PATTERNS = [
    re.compile(r"Platform:\s*(.+?)(?:\n|$)"),
    re.compile(r"(?:os|operating system):\s*(.+?)(?:\n|$)", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_system_text(data: dict[str, Any], provider: str) -> str:
    """Extract raw system prompt text from request body."""
    if provider == "anthropic":
        system = data.get("system", "")
        if isinstance(system, str):
            return system
        if isinstance(system, list):
            parts = []
            for block in system:
                if isinstance(block, dict):
                    parts.append(block.get("text", ""))
                elif isinstance(block, str):
                    parts.append(block)
            return "\n".join(parts)
    elif provider == "openai":
        messages = data.get("messages", [])
        for msg in messages:
            if isinstance(msg, dict) and msg.get("role") == "system":
                content = msg.get("content", "")
                if isinstance(content, str):
                    return content
    elif provider == "gemini":
        sys_instr = data.get("systemInstruction", {})
        if isinstance(sys_instr, dict):
            sys_parts = sys_instr.get("parts", [])
            if sys_parts and isinstance(sys_parts[0], dict):
                result: str = sys_parts[0].get("text", "")
                return result
    return ""


def _extract_system_field(
    data: dict[str, Any], provider: str, patterns: list[re.Pattern[str]], sanitize_path: bool = False
) -> str:
    """Extract a field from the system prompt using regex patterns."""
    system_text = _get_system_text(data, provider)
    if not system_text:
        return ""
    for pattern in patterns:
        match = pattern.search(system_text)
        if match:
            val = match.group(1).strip()
            if sanitize_path:
                val = val.strip("'\"")
                return val[:512]
            return val[:256]
    return ""


def _extract_working_directory(data: dict[str, Any], provider: str) -> str:
    """Extract working directory from the system prompt."""
    return _extract_system_field(data, provider, _WORKDIR_PATTERNS, sanitize_path=True)


def _derive_session_fingerprint(data: dict[str, Any], provider: str) -> str:
    """Derive session fingerprint from first 3 conversation fields."""
    parts = [provider]

    if provider == "anthropic":
        system = data.get("system", "")
        if isinstance(system, str):
            parts.append(system[:512])
        elif isinstance(system, list) and system:
            first = system[0]
            if isinstance(first, dict):
                parts.append(first.get("text", "")[:512])
        messages = data.get("messages", [])
        for msg in messages[:2]:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content[:512])
            elif isinstance(content, list) and content:
                first_block = content[0]
                if isinstance(first_block, dict):
                    parts.append(first_block.get("text", "")[:512])

    elif provider == "openai":
        messages = data.get("messages", [])
        for msg in messages[:3]:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content[:512])
            elif isinstance(content, list) and content:
                first_part = content[0]
                if isinstance(first_part, dict):
                    parts.append(first_part.get("text", "")[:512])

    elif provider == "gemini":
        sys_instr = data.get("systemInstruction", {})
        if isinstance(sys_instr, dict):
            sys_parts = sys_instr.get("parts", [])
            if sys_parts and isinstance(sys_parts[0], dict):
                parts.append(sys_parts[0].get("text", "")[:512])
        contents = data.get("contents", [])
        for cont in contents[:2]:
            if isinstance(cont, dict):
                cont_parts = cont.get("parts", [])
                if cont_parts and isinstance(cont_parts[0], dict):
                    parts.append(cont_parts[0].get("text", "")[:512])

    if len(parts) < 2:
        return ""

    key_str = "\n".join(parts)
    return hashlib.sha256(key_str.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_session(req_data: Any, provider: str, headers: dict[str, str], source_ip: str) -> SessionContext:
    """Extract session identity from request headers and body metadata.

    Args:
        req_data: Pre-parsed request body (dict, non-dict, or None).
        provider: Provider name for format-specific extraction.
        headers: Lowercased HTTP headers dict.
        source_ip: Client IP address (from request.remote).

    Returns:
        SessionContext with all extractable identity, environment, and
        project context fields populated.
    """
    ctx = SessionContext()

    # Source IP (X-Forwarded-For first, fallback to client address)
    xff = headers.get("x-forwarded-for", "")
    if xff:
        ctx.source_ip = xff.split(",")[0].strip()
    if not ctx.source_ip:
        ctx.source_ip = source_ip or ""

    # API key hash
    api_key = headers.get("x-api-key", "") or headers.get("authorization", "")
    if api_key:
        if api_key.lower().startswith("bearer "):
            api_key = api_key[7:]
        ctx.api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:16]

    # Client tool identification from User-Agent
    client_id, _, version, _ = identify_client(headers.get("user-agent", ""))
    ctx.client_name = client_id
    ctx.client_version = version

    # Explicit session header (highest priority)
    explicit_session = headers.get("x-session-id", "")
    if explicit_session:
        ctx.session_id = explicit_session[:256]

    # Normalize: only use data if it's a dict
    if not isinstance(req_data, dict):
        req_data = None

    if req_data is None:
        return ctx

    # --- From request body metadata ---
    if provider == "anthropic":
        metadata = req_data.get("metadata", {})
        if isinstance(metadata, dict):
            user_id = metadata.get("user_id", "")
            if isinstance(user_id, str) and user_id.startswith("{"):
                try:
                    user_id = json.loads(user_id)
                except (json.JSONDecodeError, ValueError):
                    log.debug("metadata.user_id looks like JSON but failed to parse")
            if isinstance(user_id, dict):
                ctx.account_id = str(user_id.get("account_uuid", ""))[:256]
                ctx.device_id = str(user_id.get("device_id", ""))[:256]
                if not ctx.session_id:
                    meta_sess = str(user_id.get("session_id", ""))[:256]
                    if meta_sess:
                        ctx.session_id = meta_sess
            elif user_id:
                ctx.account_id = str(user_id)[:256]

    elif provider == "openai":
        user = req_data.get("user", "")
        if user:
            ctx.account_id = str(user)[:256]

    # --- From system prompt ---
    ctx.working_directory = _extract_working_directory(req_data, provider)
    ctx.git_branch = _extract_system_field(req_data, provider, _GIT_BRANCH_PATTERNS)
    ctx.os_platform = _extract_system_field(req_data, provider, _OS_PLATFORM_PATTERNS)

    # --- Derived fingerprint (fallback when no session_id yet) ---
    if not ctx.session_id:
        fp = _derive_session_fingerprint(req_data, provider)
        if fp:
            ctx.session_id = "fp:%s" % fp

    log.debug(
        "session extracted: account=%s session=%s client=%s dir=%s",
        ctx.account_id[:16] if ctx.account_id else "-",
        ctx.session_id[:16] if ctx.session_id else "-",
        ctx.client_name or "-",
        ctx.working_directory[:32] if ctx.working_directory else "-",
    )

    return ctx
