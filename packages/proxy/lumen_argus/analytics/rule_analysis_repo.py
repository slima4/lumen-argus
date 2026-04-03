"""Rule analysis repository — caches overlap analysis results."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore

log = logging.getLogger("argus.analytics")


class RuleAnalysisRepository:
    """Repository for rule overlap analysis results."""

    def __init__(self, store: AnalyticsStore) -> None:
        self._store = store

    def save_analysis(
        self,
        timestamp: str,
        duration_s: float,
        total_rules: int,
        duplicates: int,
        subsets: int,
        overlaps: int,
        results_json: str,
    ) -> None:
        """Insert a new analysis result. Keeps only the latest row."""
        with self._store._connect() as conn:
            prev_dismissed = "[]"
            row = conn.execute("SELECT dismissed_json FROM rule_analysis ORDER BY id DESC LIMIT 1").fetchone()
            if row:
                prev_dismissed = row[0] or "[]"

            conn.execute("DELETE FROM rule_analysis")
            conn.execute(
                "INSERT INTO rule_analysis "
                "(timestamp, duration_s, total_rules, duplicates, subsets, overlaps, results_json, dismissed_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (timestamp, duration_s, total_rules, duplicates, subsets, overlaps, results_json, prev_dismissed),
            )
        log.debug("saved rule analysis: %d rules, %d dup, %d sub, %d ovr", total_rules, duplicates, subsets, overlaps)

    def get_latest_analysis(self) -> dict[str, Any] | None:
        """Get the most recent analysis result, or None."""
        with self._store._connect() as conn:
            row = conn.execute(
                "SELECT timestamp, duration_s, total_rules, duplicates, subsets, overlaps, "
                "results_json, dismissed_json FROM rule_analysis ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if not row:
            return None
        results: dict[str, Any] = {}
        try:
            results = json.loads(row[6])
        except (json.JSONDecodeError, TypeError) as exc:
            log.warning("could not parse results_json: %s", exc)
        dismissed: list[Any] = []
        try:
            dismissed = json.loads(row[7])
        except (json.JSONDecodeError, TypeError) as exc:
            log.warning("could not parse dismissed_json: %s", exc)
        return {
            "timestamp": row[0],
            "duration_s": row[1],
            "total_rules": row[2],
            "summary": {
                "duplicates": row[3],
                "subsets": row[4],
                "overlaps": row[5],
            },
            "duplicates": results.get("duplicates", []),
            "subsets": results.get("subsets", []),
            "overlaps": results.get("overlaps", []),
            "clusters": results.get("clusters", []),
            "quality": results["quality"],
            "dismissed": dismissed,
        }

    def get_latest_analysis_filtered(self) -> dict[str, Any] | None:
        """Get the most recent analysis with dismissed findings removed.

        Returns the result dict without the 'dismissed' key — ready for API response.
        Returns None if no analysis exists.
        """
        raw = self.get_latest_analysis()
        if not raw:
            return None
        dismissed = raw.pop("dismissed", [])
        if dismissed:
            dismissed_set = {(a, b) for a, b in dismissed}

            def _keep(item: dict[str, Any]) -> bool:
                pair = (item["rule_a"], item["rule_b"])
                reverse = (item["rule_b"], item["rule_a"])
                return pair not in dismissed_set and reverse not in dismissed_set

            raw["duplicates"] = [d for d in raw["duplicates"] if _keep(d)]
            raw["subsets"] = [s for s in raw["subsets"] if _keep(s)]
            raw["overlaps"] = [o for o in raw["overlaps"] if _keep(o)]
        return raw

    def dismiss_finding(self, rule_a: str, rule_b: str) -> bool:
        """Add a pair to the dismissed list. Returns True if added, False if already dismissed."""
        with self._store._connect() as conn:
            row = conn.execute("SELECT id, dismissed_json FROM rule_analysis ORDER BY id DESC LIMIT 1").fetchone()
            if not row:
                log.warning("dismiss_finding called but no analysis exists")
                return False

            dismissed: list[Any] = []
            try:
                dismissed = json.loads(row[1])
            except (json.JSONDecodeError, TypeError) as exc:
                log.warning("could not parse dismissed_json in dismiss_finding: %s", exc)

            pair = [rule_a, rule_b]
            reverse = [rule_b, rule_a]
            if pair in dismissed or reverse in dismissed:
                return False

            dismissed.append(pair)
            conn.execute(
                "UPDATE rule_analysis SET dismissed_json = ? WHERE id = ?",
                (json.dumps(dismissed), row[0]),
            )
        log.info("dismissed finding: %s ↔ %s", rule_a, rule_b)
        return True

    def get_dismissed_findings(self) -> list[Any]:
        """Return list of dismissed [rule_a, rule_b] pairs."""
        with self._store._connect() as conn:
            row = conn.execute("SELECT dismissed_json FROM rule_analysis ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            return []
        try:
            return json.loads(row[0])  # type: ignore[no-any-return]
        except (json.JSONDecodeError, TypeError) as exc:
            log.warning("could not parse dismissed_json in get_dismissed: %s", exc)
            return []

    def clear_analysis(self) -> None:
        """Delete all analysis data."""
        with self._store._connect() as conn:
            conn.execute("DELETE FROM rule_analysis")
        log.info("rule analysis data cleared")
