"""Rules repository — extracted from AnalyticsStore."""

import json
import logging
import re
import sqlite3
from typing import TYPE_CHECKING, Any

from lumen_argus.analytics._db import scalar

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore

log = logging.getLogger("argus.analytics")

_RULES_SCHEMA = """\
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    pattern TEXT NOT NULL,
    detector TEXT NOT NULL DEFAULT 'secrets',
    severity TEXT NOT NULL DEFAULT 'high',
    action TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    tier TEXT NOT NULL DEFAULT 'community',
    source TEXT NOT NULL DEFAULT 'import',
    description TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]',
    validator TEXT NOT NULL DEFAULT '',
    entropy_context INTEGER NOT NULL DEFAULT 0,
    hit_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_rules_detector ON rules(detector);
CREATE INDEX IF NOT EXISTS idx_rules_tier ON rules(tier);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
"""

_RULES_COLUMNS = (
    "id, name, pattern, detector, severity, action, enabled, tier, source, "
    "description, tags, validator, entropy_context, created_at, updated_at, "
    "created_by, updated_by"
)


class RulesRepository:
    """Repository for rules CRUD operations."""

    def __init__(self, store: AnalyticsStore) -> None:
        self._store = store

    def get_count(self) -> int:
        """Return total number of rules in the DB."""
        with self._store._connect() as conn:
            return scalar(conn, "SELECT COUNT(*) FROM rules")

    def get_active(self, detector: str | None = None, tier: str | None = None) -> list[dict[str, Any]]:
        """Return enabled rules, optionally filtered by detector/tier."""
        query = "SELECT " + _RULES_COLUMNS + " FROM rules WHERE enabled = 1"
        params: list[Any] = []
        if detector:
            query += " AND detector = ?"
            params.append(detector)
        if tier:
            query += " AND tier = ?"
            params.append(tier)
        query += " ORDER BY id"
        with self._store._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        result: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            d["enabled"] = bool(d.get("enabled", 1))
            if "tags" in d and isinstance(d["tags"], str):
                try:
                    d["tags"] = json.loads(d["tags"])
                except (json.JSONDecodeError, ValueError):
                    d["tags"] = []
            result.append(d)
        return result

    def get_page(
        self,
        limit: int = 50,
        offset: int = 0,
        search: str | None = None,
        detector: str | None = None,
        tier: str | None = None,
        enabled: bool | None = None,
        severity: str | None = None,
        tag: str | None = None,
    ) -> tuple[list[dict[str, Any]], Any]:
        """Paginated rules for dashboard. Returns (rules_list, total_count)."""
        conditions: list[str] = []
        params: list[Any] = []
        if search:
            terms = [t.strip() for t in search.split(",") if t.strip()]
            if len(terms) == 1:
                conditions.append("(name LIKE ? OR description LIKE ?)")
                params.extend(["%" + terms[0] + "%", "%" + terms[0] + "%"])
            elif terms:
                clauses = []
                for t in terms:
                    clauses.append("(name LIKE ? OR description LIKE ?)")
                    params.extend(["%" + t + "%", "%" + t + "%"])
                conditions.append("(" + " OR ".join(clauses) + ")")
        if detector:
            conditions.append("detector = ?")
            params.append(detector)
        if tier:
            conditions.append("tier = ?")
            params.append(tier)
        if enabled is not None:
            conditions.append("enabled = ?")
            params.append(1 if enabled else 0)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if tag:
            # Match exact tag in JSON array (e.g. '["cloud", "aws"]')
            # Using %"tag"% to avoid substring false positives
            conditions.append("tags LIKE ?")
            params.append('%"' + tag.replace('"', "") + '"%')
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""

        with self._store._connect() as conn:
            total = scalar(conn, "SELECT COUNT(*) FROM rules" + where, tuple(params))
            rows = conn.execute(
                "SELECT " + _RULES_COLUMNS + " FROM rules" + where + " ORDER BY id LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        result: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            d["enabled"] = bool(d.get("enabled", 1))
            if "tags" in d and isinstance(d["tags"], str):
                try:
                    d["tags"] = json.loads(d["tags"])
                except (json.JSONDecodeError, ValueError):
                    d["tags"] = []
            result.append(d)
        return result, total

    def get_by_name(self, name: str) -> dict[str, Any] | None:
        """Return a single rule by name."""
        with self._store._connect() as conn:
            row = conn.execute("SELECT " + _RULES_COLUMNS + " FROM rules WHERE name = ?", (name,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["enabled"] = bool(d.get("enabled", 1))
        if isinstance(d.get("tags"), str):
            try:
                d["tags"] = json.loads(d["tags"])
            except (json.JSONDecodeError, ValueError):
                d["tags"] = []
        return d

    def create(self, data: dict[str, Any]) -> dict[str, Any] | None:
        """Create a custom rule. Validates pattern regex. Returns created rule."""

        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")
        pattern = data.get("pattern", "").strip()
        if not pattern:
            raise ValueError("pattern is required")
        try:
            re.compile(pattern)
        except re.error as e:
            raise ValueError("invalid regex: %s" % e)

        now = self._store._now()
        with self._store._lock:
            with self._store._connect() as conn:
                try:
                    conn.execute(
                        "INSERT INTO rules "
                        "(name, pattern, detector, severity, action, enabled, "
                        "tier, source, description, tags, validator, entropy_context, "
                        "created_at, updated_at, created_by, updated_by) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            name,
                            pattern,
                            data.get("detector", "custom"),
                            data.get("severity", "high"),
                            data.get("action", ""),
                            1 if data.get("enabled", True) else 0,
                            data.get("tier", "custom"),
                            data.get("source", "dashboard"),
                            data.get("description", ""),
                            json.dumps(data.get("tags", [])),
                            data.get("validator", ""),
                            1 if data.get("entropy_context", False) else 0,
                            now,
                            now,
                            data.get("created_by", ""),
                            data.get("created_by", ""),
                        ),
                    )
                except sqlite3.IntegrityError:
                    raise ValueError("rule '%s' already exists" % name)
        self._store._notify_rules_changed("create", rule_name=name)
        return self.get_by_name(name)

    def _build_set_clause(self, data: dict[str, Any]) -> tuple[list[str], list[Any]]:
        """Build SET clause fragments and params from update data.

        Returns (set_fragments, params) or ([], []) if no updatable fields.
        """
        fragments: list[str] = []
        params: list[Any] = []
        for key in ("pattern", "detector", "severity", "action", "description", "validator"):
            if key in data:
                fragments.append("%s = ?" % key)
                params.append(data[key])
        if "enabled" in data:
            fragments.append("enabled = ?")
            params.append(1 if data["enabled"] else 0)
        if "tags" in data:
            fragments.append("tags = ?")
            params.append(json.dumps(data["tags"]) if isinstance(data["tags"], list) else data["tags"])
        if "entropy_context" in data:
            fragments.append("entropy_context = ?")
            params.append(1 if data["entropy_context"] else 0)
        if fragments:
            fragments.append("updated_at = ?")
            params.append(self._store._now())
            if "updated_by" in data:
                fragments.append("updated_by = ?")
                params.append(data["updated_by"])
        return fragments, params

    def update(self, name: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Update rule fields. Returns updated rule or None if not found."""
        fragments, params = self._build_set_clause(data)
        if not fragments:
            return self.get_by_name(name)
        params.append(name)

        with self._store._lock:
            with self._store._connect() as conn:
                cursor = conn.execute(
                    "UPDATE rules SET %s WHERE name = ?" % ", ".join(fragments),
                    params,
                )
                if cursor.rowcount == 0:
                    return None
        self._store._notify_rules_changed("update", rule_name=name)
        return self.get_by_name(name)

    def bulk_update(self, names: list[str], data: dict[str, Any]) -> dict[str, Any]:
        """Update multiple rules in a single transaction.

        Returns {"updated": N, "failed": [{"name": ..., "reason": ...}]}.
        """
        log.debug("bulk_update: %d names, fields=%s", len(names), list(data.keys()))
        fragments, base_params = self._build_set_clause(data)
        if not fragments:
            log.debug("bulk_update: no updatable fields, skipping")
            return {"updated": 0, "failed": []}

        set_clause = ", ".join(fragments)
        updated = 0
        failed: list[dict[str, str]] = []

        with self._store._lock:
            with self._store._connect() as conn:
                for name in names:
                    params = [*list(base_params), name]
                    cursor = conn.execute(
                        "UPDATE rules SET %s WHERE name = ?" % set_clause,
                        params,
                    )
                    if cursor.rowcount == 0:
                        failed.append({"name": name, "reason": "not found"})
                    else:
                        updated += 1

        if failed:
            log.warning("bulk_update: %d rules not found: %s", len(failed), [f["name"] for f in failed])
        if updated:
            self._store._notify_rules_changed("bulk")
            log.info("bulk_update: %d rules updated", updated)
        return {"updated": updated, "failed": failed}

    def delete(self, name: str) -> bool:
        """Delete a dashboard-created rule. Returns True if deleted."""
        with self._store._lock:
            with self._store._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM rules WHERE name = ? AND source = 'dashboard'",
                    (name,),
                )
                deleted = cursor.rowcount > 0
        if deleted:
            self._store._notify_rules_changed("delete", rule_name=name)
        return deleted

    def clone(self, name: str, new_name: str) -> dict[str, Any] | None:
        """Clone a rule as source='dashboard', tier='custom'."""
        original = self.get_by_name(name)
        if not original:
            raise ValueError("rule '%s' not found" % name)
        return self.create(
            {
                "name": new_name,
                "pattern": original["pattern"],
                "detector": original["detector"],
                "severity": original["severity"],
                "action": original["action"],
                "description": original.get("description", ""),
                "tags": original.get("tags", []),
                "validator": original.get("validator", ""),
                "entropy_context": original.get("entropy_context", False),
                "tier": "custom",
                "source": "dashboard",
                "created_by": "dashboard",
            }
        )

    def import_bulk(self, rules: list[dict[str, Any]], tier: str = "community", force: bool = False) -> dict[str, int]:
        """Bulk import rules from a JSON bundle.

        Returns {"created": N, "updated": N, "skipped": N}.
        Existing import rules: updates pattern/description/tags (preserves action/enabled).
        Dashboard/YAML rules: skipped (user-owned).
        --force: resets action/enabled to defaults for import rules.
        """

        result = {"created": 0, "updated": 0, "skipped": 0}
        now = self._store._now()

        with self._store._lock:
            with self._store._connect() as conn:
                for r in rules:
                    name = r.get("name", "").strip()
                    if not name:
                        continue
                    # Validate regex before storing
                    pattern = r.get("pattern", "")
                    if pattern:
                        try:
                            re.compile(pattern)
                        except re.error:
                            log.warning("rule '%s': invalid regex, skipping import", name)
                            result["skipped"] += 1
                            continue
                    existing = conn.execute("SELECT source, id FROM rules WHERE name = ?", (name,)).fetchone()

                    if existing:
                        source = existing[0]
                        if source in ("dashboard", "yaml"):
                            result["skipped"] += 1
                            continue
                        # Update existing import rule
                        if force:
                            conn.execute(
                                "UPDATE rules SET pattern=?, detector=?, severity=?, "
                                "action=?, enabled=1, description=?, tags=?, "
                                "validator=?, entropy_context=?, "
                                "updated_at=?, updated_by=? WHERE name=?",
                                (
                                    r.get("pattern", ""),
                                    r.get("detector", "secrets"),
                                    r.get("severity", "high"),
                                    r.get("action", ""),
                                    r.get("description", ""),
                                    json.dumps(r.get("tags", [])),
                                    r.get("validator", ""),
                                    1 if r.get("entropy_context", False) else 0,
                                    now,
                                    "cli",
                                    name,
                                ),
                            )
                        else:
                            # Preserve action and enabled
                            conn.execute(
                                "UPDATE rules SET pattern=?, detector=?, severity=?, "
                                "description=?, tags=?, validator=?, entropy_context=?, "
                                "updated_at=?, updated_by=? WHERE name=?",
                                (
                                    r.get("pattern", ""),
                                    r.get("detector", "secrets"),
                                    r.get("severity", "high"),
                                    r.get("description", ""),
                                    json.dumps(r.get("tags", [])),
                                    r.get("validator", ""),
                                    1 if r.get("entropy_context", False) else 0,
                                    now,
                                    "cli",
                                    name,
                                ),
                            )
                        result["updated"] += 1
                    else:
                        conn.execute(
                            "INSERT INTO rules "
                            "(name, pattern, detector, severity, action, enabled, "
                            "tier, source, description, tags, validator, entropy_context, "
                            "created_at, updated_at, created_by, updated_by) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                name,
                                r.get("pattern", ""),
                                r.get("detector", "secrets"),
                                r.get("severity", "high"),
                                r.get("action", ""),
                                1,
                                tier,
                                "import",
                                r.get("description", ""),
                                json.dumps(r.get("tags", [])),
                                r.get("validator", ""),
                                1 if r.get("entropy_context", False) else 0,
                                now,
                                now,
                                "cli",
                                "cli",
                            ),
                        )
                        result["created"] += 1

        if result["created"] or result["updated"]:
            self._store._notify_rules_changed("bulk")
        return result

    def export(self, tier: str | None = None, detector: str | None = None) -> list[dict[str, Any]]:
        """Export rules as dicts for JSON serialization."""
        query = "SELECT " + _RULES_COLUMNS + " FROM rules"
        conditions: list[str] = []
        params: list[Any] = []
        if tier:
            conditions.append("tier = ?")
            params.append(tier)
        if detector:
            conditions.append("detector = ?")
            params.append(detector)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY id"

        with self._store._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        result: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            d["enabled"] = bool(d.get("enabled", 1))
            if isinstance(d.get("tags"), str):
                try:
                    d["tags"] = json.loads(d["tags"])
                except (json.JSONDecodeError, ValueError):
                    d["tags"] = []
            result.append(d)
        return result

    def get_stats(self) -> dict[str, Any]:
        """Rule counts by tier, detector, enabled."""
        with self._store._connect() as conn:
            total = scalar(conn, "SELECT COUNT(*) FROM rules")
            by_tier: dict[str, Any] = {}
            for row in conn.execute("SELECT tier, COUNT(*) as cnt FROM rules GROUP BY tier"):
                by_tier[row["tier"]] = row["cnt"]
            by_detector: dict[str, Any] = {}
            for row in conn.execute("SELECT detector, COUNT(*) as cnt FROM rules GROUP BY detector"):
                by_detector[row["detector"]] = row["cnt"]
            enabled = scalar(conn, "SELECT COUNT(*) FROM rules WHERE enabled = 1")
        return {
            "total": total,
            "enabled": enabled,
            "disabled": total - enabled,
            "by_tier": by_tier,
            "by_detector": by_detector,
        }

    def get_coverage(self) -> dict[str, int]:
        """Detection coverage stats for dashboard gauge."""
        with self._store._connect() as conn:
            total = scalar(conn, "SELECT COUNT(*) FROM rules")
            active = scalar(conn, "SELECT COUNT(*) FROM rules WHERE enabled = 1")
            pro_imported = scalar(conn, "SELECT COUNT(*) FROM rules WHERE tier = 'pro'")
        return {
            "active_rules": active,
            "total_rules": total,
            "pro_imported": pro_imported,
        }

    def get_tag_stats(self) -> list[dict[str, Any]]:
        """Return tag counts for category chip display.

        Returns list of {"tag": "cloud", "total": N, "enabled": M}.
        Parses the JSON tags column and aggregates.
        """
        with self._store._connect() as conn:
            rows = conn.execute("SELECT tags, enabled FROM rules WHERE tags != '[]' AND tags != ''").fetchall()

        tag_counts: dict[str, dict[str, int]] = {}
        for row in rows:
            try:
                tags = json.loads(row["tags"])
            except (json.JSONDecodeError, TypeError):
                continue
            for t in tags:
                if t not in tag_counts:
                    tag_counts[t] = {"total": 0, "enabled": 0}
                tag_counts[t]["total"] += 1
                if row["enabled"]:
                    tag_counts[t]["enabled"] += 1

        return sorted(
            [{"tag": k, "total": v["total"], "enabled": v["enabled"]} for k, v in tag_counts.items()],
            key=lambda x: x["tag"],
        )

    def reconcile_yaml(self, custom_rules: list[Any]) -> dict[str, list[str]]:
        """Kubernetes-style reconciliation of YAML custom_rules to DB.

        YAML is authoritative for source='yaml' rules: all fields overwrite.
        Dashboard-created and import rules are never touched.

        Returns {"created": [...], "updated": [...], "deleted": [...]}.
        """

        result: dict[str, list[str]] = {"created": [], "updated": [], "deleted": []}
        now = self._store._now()

        yaml_by_name: dict[str, Any] = {}
        for rule in custom_rules:
            if not isinstance(rule, dict):
                continue
            name = rule.get("name", "")
            if not name:
                log.warning("custom_rules: rule with missing 'name' skipped")
                continue
            yaml_by_name[name] = rule

        with self._store._lock:
            with self._store._connect() as conn:
                # Snapshot YAML-sourced rules inside the lock to avoid TOCTOU
                db_yaml: dict[str, bool] = {}
                for row in conn.execute("SELECT name FROM rules WHERE source = 'yaml'").fetchall():
                    db_yaml[row[0]] = True

                # Delete YAML rules no longer in config
                for name in db_yaml:
                    if name not in yaml_by_name:
                        conn.execute("DELETE FROM rules WHERE name = ? AND source = 'yaml'", (name,))
                        result["deleted"].append(name)

                # Create or update YAML rules
                for name, rule in yaml_by_name.items():
                    pattern = str(rule.get("pattern", ""))
                    if not pattern:
                        continue
                    try:
                        re.compile(pattern)
                    except re.error:
                        log.warning("custom_rules '%s': invalid regex, skipping", name)
                        continue

                    if name in db_yaml:
                        conn.execute(
                            "UPDATE rules SET pattern=?, detector=?, severity=?, "
                            "action=?, description=?, updated_at=?, updated_by=? "
                            "WHERE name=? AND source='yaml'",
                            (
                                pattern,
                                str(rule.get("detector", "custom")),
                                str(rule.get("severity", "high")),
                                str(rule.get("action", "")),
                                str(rule.get("description", "")),
                                now,
                                "config",
                                name,
                            ),
                        )
                        result["updated"].append(name)
                    else:
                        # Check if name conflicts with non-yaml rule
                        existing = conn.execute("SELECT source FROM rules WHERE name = ?", (name,)).fetchone()
                        if existing:
                            log.warning(
                                "custom_rules '%s' conflicts with %s rule — skipping",
                                name,
                                existing[0],
                            )
                            continue
                        conn.execute(
                            "INSERT INTO rules "
                            "(name, pattern, detector, severity, action, enabled, "
                            "tier, source, description, tags, validator, entropy_context, "
                            "created_at, updated_at, created_by, updated_by) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                name,
                                pattern,
                                str(rule.get("detector", "custom")),
                                str(rule.get("severity", "high")),
                                str(rule.get("action", "")),
                                1,
                                "custom",
                                "yaml",
                                str(rule.get("description", "")),
                                "[]",
                                "",
                                0,
                                now,
                                now,
                                "config",
                                "config",
                            ),
                        )
                        result["created"].append(name)

        if result["created"] or result["updated"] or result["deleted"]:
            self._store._notify_rules_changed("bulk")
        return result
