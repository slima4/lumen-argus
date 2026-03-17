"""Configuration loading with bundled YAML-subset parser.

Python stdlib has no YAML parser. Rather than requiring PyYAML as a
dependency, we bundle a minimal recursive-descent parser that handles
the config schema: mappings, sequences, scalars, comments, and quoted strings.
No anchors, aliases, or multi-line blocks.
"""

import logging
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("argus.config")


# ---------------------------------------------------------------------------
# Minimal YAML subset parser
# ---------------------------------------------------------------------------

def _parse_yaml(text: str) -> dict:
    """Parse a YAML-subset string into a dict.

    Supports:
    - Mappings (key: value)
    - Sequences (- item)
    - Quoted and unquoted scalars
    - Comments (# ...)
    - Nested indentation
    """
    lines = text.split("\n")
    result, _ = _parse_mapping(lines, 0, 0)
    return result


def _parse_mapping(lines: list, start: int, indent: int) -> Tuple[dict, int]:
    """Parse a YAML mapping at the given indentation level."""
    result = {}
    i = start
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        # Calculate indentation
        current_indent = len(line) - len(stripped)
        if current_indent < indent:
            break
        if current_indent > indent:
            # This shouldn't happen at the top level — skip
            i += 1
            continue

        # Check for sequence item at this level
        if stripped.startswith("- "):
            break

        # Parse key: value
        colon_pos = stripped.find(":")
        if colon_pos == -1:
            i += 1
            continue

        key = stripped[:colon_pos].strip().strip('"').strip("'")
        rest = stripped[colon_pos + 1:].strip()

        # Remove inline comments
        rest = _remove_comment(rest)

        if not rest:
            # Value is a nested mapping or sequence — look at next line
            next_i = i + 1
            while next_i < len(lines):
                next_stripped = lines[next_i].lstrip()
                if next_stripped and not next_stripped.startswith("#"):
                    break
                next_i += 1

            if next_i < len(lines):
                next_line = lines[next_i]
                next_indent = len(next_line) - len(next_line.lstrip())
                next_stripped = next_line.lstrip()

                if next_indent > current_indent:
                    if next_stripped.startswith("- "):
                        val, i = _parse_sequence(lines, next_i, next_indent)
                        result[key] = val
                    else:
                        val, i = _parse_mapping(lines, next_i, next_indent)
                        result[key] = val
                else:
                    result[key] = None
                    i += 1
            else:
                result[key] = None
                i += 1
        else:
            result[key] = _parse_scalar(rest)
            i += 1

    return result, i


def _parse_sequence(lines: list, start: int, indent: int) -> Tuple[list, int]:
    """Parse a YAML sequence at the given indentation level."""
    result = []
    i = start
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()

        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        current_indent = len(line) - len(stripped)
        if current_indent < indent:
            break
        if current_indent > indent:
            i += 1
            continue

        if not stripped.startswith("- "):
            break

        item_text = stripped[2:].strip()
        item_text = _remove_comment(item_text)

        if ":" in item_text and not item_text.startswith('"') and not item_text.startswith("'"):
            # Inline mapping in sequence: - key: value
            # Check if there are more indented lines (nested mapping)
            next_i = i + 1
            while next_i < len(lines):
                ns = lines[next_i].lstrip()
                if ns and not ns.startswith("#"):
                    break
                next_i += 1

            if next_i < len(lines):
                next_indent = len(lines[next_i]) - len(lines[next_i].lstrip())
                if next_indent > current_indent + 2:
                    # Multi-line mapping under sequence item
                    first_key = item_text[:item_text.index(":")].strip().strip('"').strip("'")
                    first_val = _parse_scalar(_remove_comment(item_text[item_text.index(":") + 1:].strip()))
                    nested, i = _parse_mapping(lines, next_i, next_indent)
                    nested[first_key] = first_val
                    # Reorder so first_key is first
                    ordered = {first_key: first_val}
                    ordered.update({k: v for k, v in nested.items() if k != first_key})
                    result.append(ordered)
                    continue

            # Simple inline mapping
            colon_pos = item_text.index(":")
            k = item_text[:colon_pos].strip().strip('"').strip("'")
            v = _parse_scalar(item_text[colon_pos + 1:].strip())
            result.append({k: v})
            i += 1
        else:
            result.append(_parse_scalar(item_text))
            i += 1

    return result, i


def _parse_flow_sequence(text: str) -> Optional[list]:
    """Parse a YAML flow sequence like [a, b, c]."""
    text = text.strip()
    if not text.startswith("[") or not text.endswith("]"):
        return None
    inner = text[1:-1].strip()
    if not inner:
        return []
    items = []
    for item in inner.split(","):
        items.append(_parse_scalar(item.strip()))
    return items


def _parse_scalar(text: str) -> Any:
    """Parse a scalar value."""
    if not text:
        return None

    # Flow sequence [a, b, c]
    if text.startswith("[") and text.endswith("]"):
        result = _parse_flow_sequence(text)
        if result is not None:
            return result

    # Quoted string
    if (text.startswith('"') and text.endswith('"')) or \
       (text.startswith("'") and text.endswith("'")):
        return text[1:-1]

    # Boolean
    lower = text.lower()
    if lower in ("true", "yes", "on"):
        return True
    if lower in ("false", "no", "off"):
        return False
    if lower == "null" or lower == "~":
        return None

    # Number
    try:
        if "." in text:
            return float(text)
        return int(text)
    except ValueError:
        pass

    return text


def _remove_comment(text: str) -> str:
    """Remove trailing inline comment, respecting quoted strings."""
    in_quote = None
    for i, c in enumerate(text):
        if c in ('"', "'") and in_quote is None:
            in_quote = c
        elif c == in_quote:
            in_quote = None
        elif c == '#' and in_quote is None:
            # Make sure it's preceded by whitespace
            if i > 0 and text[i - 1] in (' ', '\t'):
                return text[:i].rstrip()
    return text


# ---------------------------------------------------------------------------
# Config dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ProxyConfig:
    port: int = 8080
    bind: str = "127.0.0.1"
    timeout: int = 120
    retries: int = 1
    max_body_size: int = 50 * 1024 * 1024  # 50MB


@dataclass
class DetectorConfig:
    enabled: bool = True
    action: str = ""       # empty = use default_action


@dataclass
class AllowlistConfig:
    secrets: List[str] = field(default_factory=list)
    pii: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)


@dataclass
class AuditConfig:
    log_dir: str = "~/.lumen-argus/audit"
    retention_days: int = 90
    include_request_summary: bool = True


@dataclass
class LoggingConfig:
    log_dir: str = "~/.lumen-argus/logs"
    file_level: str = "info"
    max_size_mb: int = 10
    backup_count: int = 5


@dataclass
class Config:
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    default_action: str = "alert"
    secrets: DetectorConfig = field(default_factory=DetectorConfig)
    pii: DetectorConfig = field(default_factory=DetectorConfig)
    proprietary: DetectorConfig = field(default_factory=DetectorConfig)
    entropy_threshold: float = 4.5
    allowlist: AllowlistConfig = field(default_factory=AllowlistConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    logging_config: LoggingConfig = field(default_factory=LoggingConfig)
    upstreams: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_VALID_ACTIONS = {"log", "alert", "redact", "block"}

_KNOWN_TOP_KEYS = {
    "version", "proxy", "default_action", "detectors",
    "allowlists", "audit", "logging", "notifications", "custom_rules",
    # Pro/Enterprise extension keys (read by lumen-argus-pro plugin)
    "license_key", "redaction", "dashboard", "analytics", "enterprise",
    "custom_detectors",
}
_KNOWN_PROXY_KEYS = {"port", "bind", "upstream", "timeout", "retries", "max_body_size"}
_KNOWN_DETECTOR_KEYS = {"enabled", "action", "entropy_threshold", "severity_threshold", "patterns", "types", "keywords", "file_patterns"}
_KNOWN_AUDIT_KEYS = {"log_dir", "retention_days", "include_request_summary", "redact_findings_in_log"}
_KNOWN_LOGGING_KEYS = {"log_dir", "file_level", "max_size_mb", "backup_count", "format", "output"}


def _warn(msg: str) -> None:
    """Log a config warning. Falls through to stderr via logging handlers."""
    log.warning("%s", msg)


def _validate_config(data: dict, source: str) -> List[str]:
    """Validate parsed config data. Returns list of warnings."""
    warnings = []  # type: List[str]

    if not isinstance(data, dict):
        warnings.append("%s: config root must be a mapping" % source)
        return warnings

    # Check for unknown top-level keys
    for key in data:
        if key not in _KNOWN_TOP_KEYS:
            warnings.append("%s: unknown key '%s'" % (source, key))

    # Validate default_action
    if "default_action" in data:
        action = str(data["default_action"])
        if action not in _VALID_ACTIONS:
            warnings.append(
                "%s: default_action '%s' is not valid (expected: %s)"
                % (source, action, ", ".join(sorted(_VALID_ACTIONS)))
            )

    # Validate proxy section
    proxy = data.get("proxy", {})
    if isinstance(proxy, dict):
        for key in proxy:
            if key not in _KNOWN_PROXY_KEYS:
                warnings.append("%s: unknown key 'proxy.%s'" % (source, key))
        if "port" in proxy:
            try:
                port = int(proxy["port"])
                if port < 1 or port > 65535:
                    warnings.append("%s: proxy.port %d is out of range (1-65535)" % (source, port))
            except (ValueError, TypeError):
                warnings.append("%s: proxy.port must be an integer" % source)
        if "bind" in proxy:
            bind = str(proxy["bind"])
            if bind not in ("127.0.0.1", "localhost"):
                warnings.append(
                    "%s: proxy.bind '%s' is not allowed (must be 127.0.0.1 or localhost)"
                    % (source, bind)
                )
        if "timeout" in proxy:
            try:
                t = int(proxy["timeout"])
                if t < 1 or t > 300:
                    warnings.append("%s: proxy.timeout %d is out of range (1-300)" % (source, t))
            except (ValueError, TypeError):
                warnings.append("%s: proxy.timeout must be an integer" % source)
        if "retries" in proxy:
            try:
                r = int(proxy["retries"])
                if r < 0 or r > 5:
                    warnings.append("%s: proxy.retries %d is out of range (0-5)" % (source, r))
            except (ValueError, TypeError):
                warnings.append("%s: proxy.retries must be an integer" % source)

    # Validate detector sections
    detectors = data.get("detectors", {})
    if isinstance(detectors, dict):
        for det_name in ("secrets", "pii", "proprietary"):
            det = detectors.get(det_name, {})
            if isinstance(det, dict):
                for key in det:
                    if key not in _KNOWN_DETECTOR_KEYS:
                        warnings.append("%s: unknown key 'detectors.%s.%s'" % (source, det_name, key))
                if "action" in det:
                    action = str(det["action"])
                    if action not in _VALID_ACTIONS:
                        warnings.append(
                            "%s: detectors.%s.action '%s' is not valid (expected: %s)"
                            % (source, det_name, action, ", ".join(sorted(_VALID_ACTIONS)))
                        )
                if "entropy_threshold" in det:
                    try:
                        threshold = float(det["entropy_threshold"])
                        if threshold < 0 or threshold > 10:
                            warnings.append(
                                "%s: detectors.%s.entropy_threshold %.1f is out of range (0-10)"
                                % (source, det_name, threshold)
                            )
                    except (ValueError, TypeError):
                        warnings.append(
                            "%s: detectors.%s.entropy_threshold must be a number"
                            % (source, det_name)
                        )

    # Validate audit section
    audit = data.get("audit", {})
    if isinstance(audit, dict):
        for key in audit:
            if key not in _KNOWN_AUDIT_KEYS:
                warnings.append("%s: unknown key 'audit.%s'" % (source, key))
        if "retention_days" in audit:
            try:
                days = int(audit["retention_days"])
                if days < 1:
                    warnings.append("%s: audit.retention_days must be positive" % source)
            except (ValueError, TypeError):
                warnings.append("%s: audit.retention_days must be an integer" % source)

    # Validate logging section
    logging_sec = data.get("logging", {})
    if isinstance(logging_sec, dict):
        for key in logging_sec:
            if key not in _KNOWN_LOGGING_KEYS:
                warnings.append("%s: unknown key 'logging.%s'" % (source, key))
        if "file_level" in logging_sec:
            lvl = str(logging_sec["file_level"]).lower()
            if lvl not in ("debug", "info", "warning", "error"):
                warnings.append(
                    "%s: logging.file_level '%s' is not valid (expected: debug, info, warning, error)"
                    % (source, lvl)
                )
        if "max_size_mb" in logging_sec:
            try:
                sz = int(logging_sec["max_size_mb"])
                if sz < 1:
                    warnings.append("%s: logging.max_size_mb must be positive" % source)
            except (ValueError, TypeError):
                warnings.append("%s: logging.max_size_mb must be an integer" % source)
        if "backup_count" in logging_sec:
            try:
                bc = int(logging_sec["backup_count"])
                if bc < 0:
                    warnings.append("%s: logging.backup_count must be non-negative" % source)
            except (ValueError, TypeError):
                warnings.append("%s: logging.backup_count must be an integer" % source)
        if "format" in logging_sec:
            fmt = str(logging_sec["format"]).lower()
            if fmt not in ("text", "json"):
                warnings.append(
                    "%s: logging.format '%s' is not valid (expected: text, json)"
                    % (source, fmt)
                )
            elif fmt == "json":
                warnings.append(
                    "%s: JSON log format requires Pro license" % source
                )

    # Validate allowlists section
    al = data.get("allowlists", {})
    if isinstance(al, dict):
        for key in al:
            if key not in ("secrets", "pii", "paths"):
                warnings.append("%s: unknown key 'allowlists.%s'" % (source, key))
        for list_key in ("secrets", "pii", "paths"):
            val = al.get(list_key)
            if val is not None and not isinstance(val, list):
                warnings.append("%s: allowlists.%s must be a list" % (source, list_key))

    return warnings


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def _check_unsupported_yaml(text: str, source: str) -> List[str]:
    """Detect unsupported YAML syntax and return warnings."""
    warnings = []  # type: List[str]
    for lineno, line in enumerate(text.split("\n"), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Block scalars (| or >)
        if re.match(r"^[^#]*:\s*[|>]\s*$", stripped):
            warnings.append(
                "%s line %d: multi-line block scalars (| or >) are not supported, "
                "use quoted strings instead" % (source, lineno)
            )
        # Anchors and aliases
        if re.match(r"^[^#]*[&*]\w+", stripped) and not stripped.startswith("-"):
            # Avoid false positives on glob patterns in allowlists
            colon_pos = stripped.find(":")
            if colon_pos == -1 or stripped.find("&") < colon_pos or stripped.find("*") < colon_pos:
                pass  # could be an anchor in a key position — unlikely in our schema
        # Flow mappings {key: value}
        colon_pos = stripped.find(":")
        if colon_pos != -1:
            value = stripped[colon_pos + 1:].strip()
            value = _remove_comment(value)
            if value.startswith("{") and value.endswith("}"):
                warnings.append(
                    "%s line %d: flow mappings ({...}) are not supported, "
                    "use indented key: value pairs instead" % (source, lineno)
                )
    return warnings


_DEFAULT_CONFIG = """\
# lumen-argus configuration
# Docs: https://github.com/slima4/lumen-argus
version: "1"

proxy:
  port: 8080
  bind: "127.0.0.1"
  timeout: 120
  retries: 1

# Global default action: log | alert | block
default_action: alert

detectors:
  secrets:
    enabled: true
    action: block
    entropy_threshold: 4.5

  pii:
    enabled: true
    action: alert

  proprietary:
    enabled: true
    action: alert

# Never flag these
allowlists:
  secrets:
    - "AKIAIOSFODNN7EXAMPLE"
    - "sk-ant-api03-example"
  pii:
    - "*@example.com"
    - "*@test.local"
  paths:
    - "test/**"
    - "tests/**"
    - "fixtures/**"

audit:
  log_dir: "~/.lumen-argus/audit"
  retention_days: 90

# Application logging (file rotation)
logging:
  log_dir: "~/.lumen-argus/logs"
  file_level: info
  max_size_mb: 10
  backup_count: 5
"""


def _create_default_config(path: Path) -> None:
    """Create a default config file on first run."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_DEFAULT_CONFIG, encoding="utf-8")
        _warn("created default config at %s" % path)
    except OSError:
        pass  # Non-fatal — will use in-memory defaults


def load_config(
    config_path: Optional[str] = None,
    project_path: Optional[str] = None,
) -> Config:
    """Load and merge configuration from global and project YAML files.

    Args:
        config_path: Path to global config. Defaults to ~/.lumen-argus/config.yaml.
        project_path: Path to project-level .lumen-argus.yaml.

    Returns:
        Merged Config object.
    """
    config = Config()

    # Load global config — create default on first run
    global_path = Path(os.path.expanduser(config_path or "~/.lumen-argus/config.yaml"))
    if not global_path.exists() and config_path is None:
        _create_default_config(global_path)
    if global_path.exists():
        try:
            text = global_path.read_text(encoding="utf-8")
            for w in _check_unsupported_yaml(text, str(global_path)):
                _warn(w)
            data = _parse_yaml(text)
            for w in _validate_config(data, str(global_path)):
                _warn(w)
            _apply_config(config, data)
            log.debug("loaded config from %s", global_path)
        except Exception as e:
            log.error("failed to parse %s: %s (using defaults)", global_path, e)

    # Load project config (can only be more restrictive)
    if project_path:
        proj = Path(project_path)
    else:
        proj = Path.cwd() / ".lumen-argus.yaml"

    if proj.exists():
        try:
            text = proj.read_text(encoding="utf-8")
            for w in _check_unsupported_yaml(text, str(proj)):
                _warn(w)
            data = _parse_yaml(text)
            for w in _validate_config(data, str(proj)):
                _warn(w)
            _apply_project_config(config, data)
        except Exception as e:
            log.error("failed to parse %s: %s (using defaults)", proj, e)

    return config


def _apply_config(config: Config, data: dict) -> None:
    """Apply parsed YAML data to config object."""
    if not isinstance(data, dict):
        return

    # Proxy settings
    proxy = data.get("proxy", {})
    if isinstance(proxy, dict):
        if "port" in proxy:
            config.proxy.port = int(proxy["port"])
        if "bind" in proxy:
            config.proxy.bind = str(proxy["bind"])
        if "timeout" in proxy:
            config.proxy.timeout = int(proxy["timeout"])
        if "retries" in proxy:
            config.proxy.retries = int(proxy["retries"])
        if "max_body_size" in proxy:
            config.proxy.max_body_size = int(proxy["max_body_size"])
        upstream = proxy.get("upstream", {})
        if isinstance(upstream, dict):
            config.upstreams.update(upstream)

    # Default action
    if "default_action" in data:
        config.default_action = str(data["default_action"])

    # Detector settings
    detectors = data.get("detectors", {})
    if isinstance(detectors, dict):
        for name, det_config in [("secrets", config.secrets), ("pii", config.pii), ("proprietary", config.proprietary)]:
            det_data = detectors.get(name, {})
            if isinstance(det_data, dict):
                if "enabled" in det_data:
                    det_config.enabled = bool(det_data["enabled"])
                if "action" in det_data:
                    det_config.action = str(det_data["action"])
                if "entropy_threshold" in det_data:
                    config.entropy_threshold = float(det_data["entropy_threshold"])

    # Allowlists
    al = data.get("allowlists", {})
    if isinstance(al, dict):
        if "secrets" in al and isinstance(al["secrets"], list):
            config.allowlist.secrets = [str(s) for s in al["secrets"]]
        if "pii" in al and isinstance(al["pii"], list):
            config.allowlist.pii = [str(s) for s in al["pii"]]
        if "paths" in al and isinstance(al["paths"], list):
            config.allowlist.paths = [str(s) for s in al["paths"]]

    # Audit
    audit = data.get("audit", {})
    if isinstance(audit, dict):
        if "log_dir" in audit:
            config.audit.log_dir = str(audit["log_dir"])
        if "retention_days" in audit:
            config.audit.retention_days = int(audit["retention_days"])
        if "include_request_summary" in audit:
            config.audit.include_request_summary = bool(audit["include_request_summary"])

    # Logging
    logging_sec = data.get("logging", {})
    if isinstance(logging_sec, dict):
        if "log_dir" in logging_sec:
            config.logging_config.log_dir = str(logging_sec["log_dir"])
        if "file_level" in logging_sec:
            config.logging_config.file_level = str(logging_sec["file_level"]).lower()
        if "max_size_mb" in logging_sec:
            config.logging_config.max_size_mb = int(logging_sec["max_size_mb"])
        if "backup_count" in logging_sec:
            config.logging_config.backup_count = int(logging_sec["backup_count"])


def _apply_project_config(config: Config, data: dict) -> None:
    """Apply project-level overrides. Can only be MORE restrictive."""
    if not isinstance(data, dict):
        return

    ACTION_PRIORITY = {"block": 4, "redact": 3, "alert": 2, "log": 1}

    detectors = data.get("detectors", {})
    if isinstance(detectors, dict):
        for name, det_config in [("secrets", config.secrets), ("pii", config.pii), ("proprietary", config.proprietary)]:
            det_data = detectors.get(name, {})
            if isinstance(det_data, dict):
                # Can only upgrade action severity, not downgrade
                if "action" in det_data:
                    new_action = str(det_data["action"])
                    old_priority = ACTION_PRIORITY.get(det_config.action, 0)
                    new_priority = ACTION_PRIORITY.get(new_action, 0)
                    if new_priority > old_priority:
                        det_config.action = new_action

    # Allowlists — project can add to allowlists
    al = data.get("allowlists", {})
    if isinstance(al, dict):
        if "secrets" in al and isinstance(al["secrets"], list):
            config.allowlist.secrets.extend(str(s) for s in al["secrets"])
        if "pii" in al and isinstance(al["pii"], list):
            config.allowlist.pii.extend(str(s) for s in al["pii"])
        if "paths" in al and isinstance(al["paths"], list):
            config.allowlist.paths.extend(str(s) for s in al["paths"])
