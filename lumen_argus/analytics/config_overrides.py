"""Config overrides repository — extracted from AnalyticsStore."""

import logging

log = logging.getLogger("argus.analytics")

_CONFIG_OVERRIDES_SCHEMA = """\
CREATE TABLE IF NOT EXISTS config_overrides (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

# Community-editable config keys with validation rules
_VALID_CONFIG_KEYS = {
    "proxy.timeout",
    "proxy.retries",
    "default_action",
    "detectors.secrets.enabled",
    "detectors.pii.enabled",
    "detectors.proprietary.enabled",
    "detectors.secrets.action",
    "detectors.pii.action",
    "detectors.proprietary.action",
    "pipeline.stages.outbound_dlp.enabled",
    "pipeline.stages.encoding_decode.enabled",
    "pipeline.stages.encoding_decode.base64",
    "pipeline.stages.encoding_decode.hex",
    "pipeline.stages.encoding_decode.url",
    "pipeline.stages.encoding_decode.unicode",
    "pipeline.stages.encoding_decode.max_depth",
    "pipeline.stages.encoding_decode.min_decoded_length",
    "pipeline.stages.encoding_decode.max_decoded_length",
    "pipeline.stages.response_secrets.enabled",
    "pipeline.stages.response_injection.enabled",
    "pipeline.stages.mcp_arguments.enabled",
    "pipeline.stages.mcp_responses.enabled",
    "pipeline.stages.websocket_outbound.enabled",
    "pipeline.stages.websocket_inbound.enabled",
    "pipeline.parallel_batching",
}

_VALID_ACTIONS = {"log", "alert", "block"}


class ConfigOverridesRepository:
    """Repository for config override CRUD operations."""

    def __init__(self, store):
        self._store = store

    def get_all(self):
        """Return all config overrides as a dict."""
        with self._store._connect() as conn:
            rows = conn.execute("SELECT key, value FROM config_overrides").fetchall()
        overrides = {row["key"]: row["value"] for row in rows}
        log.debug("loaded %d config override(s) from DB", len(overrides))
        return overrides

    def set(self, key, value):
        """Set a config override. Validates key and value."""
        if key not in _VALID_CONFIG_KEYS:
            raise ValueError("Invalid config key: %s" % key)

        value = str(value)
        if key == "proxy.timeout":
            try:
                v = int(value)
            except (ValueError, TypeError):
                raise ValueError("timeout must be an integer (1-300)")
            if v < 1 or v > 300:
                raise ValueError("timeout must be 1-300")
        elif key == "proxy.retries":
            try:
                v = int(value)
            except (ValueError, TypeError):
                raise ValueError("retries must be an integer (0-10)")
            if v < 0 or v > 10:
                raise ValueError("retries must be 0-10")
        elif key in (
            "default_action",
            "detectors.secrets.action",
            "detectors.pii.action",
            "detectors.proprietary.action",
        ):
            if value not in _VALID_ACTIONS:
                raise ValueError("action must be one of: %s" % ", ".join(sorted(_VALID_ACTIONS)))
        elif key == "pipeline.parallel_batching":
            if value.lower() not in ("true", "false"):
                raise ValueError("parallel_batching must be true or false")
            value = value.lower()
        elif key.endswith(".enabled") or key.endswith((".base64", ".hex", ".url", ".unicode")):
            if value.lower() not in ("true", "false"):
                raise ValueError("%s must be true or false" % key)
            value = value.lower()  # normalize
        elif key == "pipeline.stages.encoding_decode.max_depth":
            try:
                v = int(value)
            except (ValueError, TypeError):
                raise ValueError("max_depth must be an integer (1-5)")
            if v < 1 or v > 5:
                raise ValueError("max_depth must be 1-5")
        elif key == "pipeline.stages.encoding_decode.min_decoded_length":
            try:
                v = int(value)
            except (ValueError, TypeError):
                raise ValueError("min_decoded_length must be an integer (1-100)")
            if v < 1 or v > 100:
                raise ValueError("min_decoded_length must be 1-100")
        elif key == "pipeline.stages.encoding_decode.max_decoded_length":
            try:
                v = int(value)
            except (ValueError, TypeError):
                raise ValueError("max_decoded_length must be an integer (100-1000000)")
            if v < 100 or v > 1_000_000:
                raise ValueError("max_decoded_length must be 100-1000000")

        now = self._store._now()
        with self._store._lock:
            with self._store._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO config_overrides (key, value, updated_at) VALUES (?, ?, ?)",
                    (key, value, now),
                )
        log.debug("config override stored: %s = %s", key, value)

    def delete(self, key):
        """Delete a config override (revert to YAML default)."""
        with self._store._lock:
            with self._store._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM config_overrides WHERE key = ?",
                    (key,),
                )
                deleted = cursor.rowcount > 0
        if deleted:
            log.info("config override deleted: %s (reverted to YAML default)", key)
        return deleted
