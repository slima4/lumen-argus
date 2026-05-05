"""Action execution: dispatch block/alert/log actions."""

import json
import logging
import re
from typing import Any

from lumen_argus.models import ScanResult

log = logging.getLogger("argus.actions")

# Match extractor location formats by canonical prefix; trailing subpaths
# (e.g. nested ".content[K]" emitted for tool_result blocks) are tolerated
# and discarded — strip operates on the outer message/block index, and any
# nested content goes away with its parent block. Boundary "(?:\.|$)" keeps
# unrelated identifiers like "content_extra" from matching.
#   "messages[N].content"          — string content
#   "messages[N].content.<sub>"    — string content with subpath
#   "messages[N].content[M]"       — array content block
#   "messages[N].content[M].<sub>" — array content block with subpath
_MSG_CONTENT_RE = re.compile(r"messages\[(\d+)\]\.content(?:\.|$)")
_CONTENT_BLOCK_RE = re.compile(r"messages\[(\d+)\]\.content\[(\d+)\](?:\.|$)")


def build_block_response(result: ScanResult) -> bytes:
    """Build a JSON error response matching Anthropic's API error format.

    Uses HTTP 400 + "invalid_request_error" type so that Claude Code
    displays the message cleanly. HTTP 403 triggers Claude Code's
    "Please run /login" auth error handler regardless of the body.
    """
    types = ", ".join(f.type for f in result.findings)
    message = (
        "[lumen-argus] Request blocked — sensitive data detected (%s). "
        "Your message was NOT sent to the API. "
        "Remove the sensitive data and try again." % types
    )

    body = {
        "type": "error",
        "error": {
            "type": "invalid_request_error",
            "message": message,
        },
    }
    return json.dumps(body).encode("utf-8")


def should_forward(result: ScanResult) -> bool:
    """Return True if the request should be forwarded to upstream."""
    return result.action != "block"


def try_strip_blocked_history(req_data: dict[str, Any], findings: list[Any]) -> bytes | None:
    """Strip content containing blocked findings from conversation history.

    AI tools like Claude Code pack the entire conversation into a single
    message with multiple content blocks: messages[0].content = [{block0},
    {block1}, ...]. The user's latest input is the last content block(s).

    This function handles two structures:
    - Multi-message: findings in earlier messages (not the last user message)
    - Multi-block: findings in earlier content blocks within the same message

    Returns:
        Cleaned body bytes if stripping is possible, None if full block needed.
    """
    if not req_data or not isinstance(req_data, dict):
        return None

    messages = req_data.get("messages")
    if not messages or not isinstance(messages, list):
        return None

    # Parse finding locations into (msg_index, block_index) pairs.
    # block_index is None for "messages[N].content" (string content).
    finding_locations = []
    for f in findings:
        m = _CONTENT_BLOCK_RE.match(f.location)
        if m:
            finding_locations.append((int(m.group(1)), int(m.group(2))))
            continue
        m = _MSG_CONTENT_RE.match(f.location)
        if m:
            finding_locations.append((int(m.group(1)), -1))

    if not finding_locations:
        log.debug("strip: no parseable finding locations, cannot strip")
        return None

    # Find the last user message index
    last_user_idx = -1
    for i in range(len(messages) - 1, -1, -1):
        if isinstance(messages[i], dict) and messages[i].get("role") == "user":
            last_user_idx = i
            break

    if last_user_idx < 0:
        log.debug("strip: no user message found in %d messages", len(messages))
        return None

    log.debug(
        "strip: %d findings at %s, %d messages, last_user_idx=%d",
        len(finding_locations),
        finding_locations,
        len(messages),
        last_user_idx,
    )

    # Check if any finding is in a DIFFERENT message than the last user message.
    # If so, use message-level stripping.
    finding_msg_indices = {loc[0] for loc in finding_locations}
    non_last_msg_findings = finding_msg_indices - {last_user_idx}

    if non_last_msg_findings:
        # Findings in earlier messages — strip entire messages
        if last_user_idx in finding_msg_indices:
            log.debug("strip: findings in both history and latest message, must block")
            return None
        indices_to_strip = set()
        for idx in non_last_msg_findings:
            indices_to_strip.add(idx)
            # Also strip assistant reply following a stripped user message
            if (
                idx + 1 < len(messages)
                and isinstance(messages[idx + 1], dict)
                and messages[idx + 1].get("role") == "assistant"
            ):
                indices_to_strip.add(idx + 1)
        cleaned_messages = [msg for i, msg in enumerate(messages) if i not in indices_to_strip]
        if not cleaned_messages:
            log.debug("strip: all messages would be removed, must block")
            return None
        log.debug("strip: removing %d message(s) at indices %s", len(indices_to_strip), sorted(indices_to_strip))
        cleaned_data = dict(req_data)
        cleaned_data["messages"] = cleaned_messages
        return json.dumps(cleaned_data).encode("utf-8")

    # All findings are within the last user message (same msg index).
    # Check if we can strip individual content blocks.
    last_msg = messages[last_user_idx]
    content = last_msg.get("content") if isinstance(last_msg, dict) else None
    if not isinstance(content, list):
        log.debug("strip: last message content is string (not blocks), cannot strip partially")
        return None

    # Find which content blocks have findings
    finding_block_indices = set()
    for msg_idx, block_idx in finding_locations:
        if msg_idx == last_user_idx and block_idx >= 0:
            if block_idx >= len(content):
                log.debug("strip: block_idx %d out of range (content len=%d), must block", block_idx, len(content))
                return None
            finding_block_indices.add(block_idx)
        else:
            log.debug("strip: finding without block index in last message, must block")
            return None

    # The latest user input is at the end of the content array.
    # If the finding is in the LAST content block, the user just typed
    # sensitive data — must block.
    last_block_idx = len(content) - 1
    if last_block_idx in finding_block_indices:
        log.debug(
            "strip: finding in last content block [%d] (user's new input), must block",
            last_block_idx,
        )
        return None

    log.debug(
        "strip: removing content blocks %s from messages[%d] (%d total blocks)",
        sorted(finding_block_indices),
        last_user_idx,
        len(content),
    )

    # Strip the content blocks with findings
    cleaned_content = [block for i, block in enumerate(content) if i not in finding_block_indices]
    if not cleaned_content:
        log.debug("strip: all content blocks would be removed, must block")
        return None

    cleaned_messages = list(messages)
    cleaned_msg = dict(last_msg)
    cleaned_msg["content"] = cleaned_content
    cleaned_messages[last_user_idx] = cleaned_msg

    cleaned_data = dict(req_data)
    cleaned_data["messages"] = cleaned_messages
    return json.dumps(cleaned_data).encode("utf-8")
