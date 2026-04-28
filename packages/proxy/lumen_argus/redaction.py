"""Redaction action — replace matched sensitive substrings with typed placeholders."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lumen_argus.models import Finding, SessionContext


def redact_request_body(body: bytes, findings: list[Finding], _session: SessionContext) -> bytes:
    """Replace ``matched_value`` strings of redact-action findings with ``[REDACTED:{type}]``.

    Longest matches first to avoid corrupting overlapping substrings.
    Deduplicates by value: first finding's ``type`` wins for the placeholder.
    """
    redactable = [f for f in findings if f.action == "redact" and f.matched_value]
    if not redactable:
        return body

    text = body.decode("utf-8", errors="replace")
    value_to_type: dict[str, str] = {}
    for f in redactable:
        value_to_type.setdefault(f.matched_value, f.type)

    for value in sorted(value_to_type, key=len, reverse=True):
        text = text.replace(value, f"[REDACTED:{value_to_type[value]}]")
    return text.encode("utf-8")
