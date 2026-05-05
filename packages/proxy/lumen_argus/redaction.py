"""Redaction action — replace matched sensitive substrings with typed placeholders."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lumen_argus.models import SEVERITY_ORDER

if TYPE_CHECKING:
    from lumen_argus.models import Finding, SessionContext


def redact_request_body(body: bytes, findings: list[Finding], _session: SessionContext) -> bytes:
    """Replace ``matched_value`` strings of redact-action findings with ``[REDACTED:{type}]``.

    Placeholder-type contract: when multiple findings share a ``matched_value``,
    the placeholder ``type`` is picked deterministically — highest severity first,
    ties broken by ``(detector, type)`` ascending. Result is independent of
    detector registration order, so adding a priority-prepended detector cannot
    silently rename existing placeholders. Longest matches first when applying
    substitutions to avoid corrupting overlapping substrings.
    """
    redactable = [f for f in findings if f.action == "redact" and f.matched_value]
    if not redactable:
        return body

    text = body.decode("utf-8", errors="replace")
    redactable.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, -1), f.detector, f.type))
    value_to_type: dict[str, str] = {}
    for f in redactable:
        value_to_type.setdefault(f.matched_value, f.type)

    for value in sorted(value_to_type, key=len, reverse=True):
        text = text.replace(value, f"[REDACTED:{value_to_type[value]}]")
    return text.encode("utf-8")
