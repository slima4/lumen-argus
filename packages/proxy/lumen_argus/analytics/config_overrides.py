"""Config overrides repository — extracted from AnalyticsStore."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from lumen_argus.analytics.base import BaseRepository

if TYPE_CHECKING:
    from lumen_argus.analytics.adapter import DatabaseAdapter

log = logging.getLogger("argus.analytics")

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
    "proxy.port",
    "proxy.bind",
    "proxy.mode",
}

_VALID_ACTIONS = {"log", "alert", "block"}


class ConfigOverridesRepository(BaseRepository):
    """Repository for config override CRUD operations."""

    def __init__(self, adapter: DatabaseAdapter) -> None:
        super().__init__(adapter)

    def get_all(self, namespace_id: int = 1) -> dict[str, Any]:
        """Return all config overrides as a dict."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT key, value FROM config_overrides WHERE namespace_id = ?",
                (namespace_id,),
            ).fetchall()
        overrides = {row["key"]: row["value"] for row in rows}
        log.debug("loaded %d config override(s) from DB", len(overrides))
        return overrides

    def set(self, key: str, value: Any, namespace_id: int = 1) -> None:
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
        elif key == "proxy.port":
            try:
                v = int(value)
            except (ValueError, TypeError):
                raise ValueError("port must be an integer (1-65535)")
            if v < 1 or v > 65535:
                raise ValueError("port must be 1-65535")
        elif key == "proxy.bind":
            import ipaddress

            addr = value.strip()
            if addr not in ("localhost",):
                try:
                    ipaddress.ip_address(addr)
                except ValueError:
                    raise ValueError("bind must be a valid IP address or 'localhost'")
            value = addr
        elif key == "proxy.mode":
            if value not in ("active", "passthrough"):
                raise ValueError("mode must be 'active' or 'passthrough'")
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
        elif key.endswith((".enabled", ".base64", ".hex", ".url", ".unicode")):
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

        now = self._now()
        with self._adapter.write_lock():
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO config_overrides "
                    "(namespace_id, key, value, updated_at) VALUES (?, ?, ?, ?)",
                    (namespace_id, key, value, now),
                )
        log.debug("config override stored: %s = %s", key, value)

    def delete(self, key: str, namespace_id: int = 1) -> bool:
        """Delete a config override (revert to YAML default)."""
        with self._adapter.write_lock():
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM config_overrides WHERE key = ? AND namespace_id = ?",
                    (key, namespace_id),
                )
                deleted = cursor.rowcount > 0
        if deleted:
            log.info("config override deleted: %s (reverted to YAML default)", key)
        return deleted
