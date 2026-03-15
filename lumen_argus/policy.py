"""Policy engine: evaluate findings and determine action."""

from dataclasses import dataclass
from typing import List

from lumen_argus.models import Finding

ACTION_PRIORITY = {"block": 4, "redact": 3, "alert": 2, "log": 1}


@dataclass
class ActionDecision:
    """The resolved action after evaluating all findings."""
    action: str             # winning action
    reason: str             # which finding triggered it
    findings: List[Finding]  # all findings


class PolicyEngine:
    """Evaluates detection findings against policy and returns the winning action."""

    def __init__(self, default_action: str = "alert", action_overrides: dict = None):
        """
        Args:
            default_action: Default action when a finding has no specific action.
            action_overrides: Per-detector action overrides, e.g. {"secrets": "block"}.
        """
        self._default_action = default_action
        self._overrides = action_overrides or {}

    def evaluate(self, findings: List[Finding]) -> ActionDecision:
        """Evaluate all findings and return the highest-priority action."""
        if not findings:
            return ActionDecision(action="pass", reason="", findings=[])

        # Assign action to each finding based on overrides
        for f in findings:
            if not f.action:
                f.action = self._overrides.get(f.detector, self._default_action)

        # Find highest-priority action
        best_action = "log"
        best_finding = findings[0]
        best_priority = 0

        for f in findings:
            p = ACTION_PRIORITY.get(f.action, 0)
            if p > best_priority:
                best_priority = p
                best_action = f.action
                best_finding = f

        return ActionDecision(
            action=best_action,
            reason="%s (%s)" % (best_finding.type, best_finding.location),
            findings=findings,
        )
