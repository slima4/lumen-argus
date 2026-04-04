"""Configuration file I/O — reads YAML files, merges global + project configs.

Changes when: file discovery logic, merging strategy, or default template changes.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml

from lumen_argus.config.apply import _apply_config, _apply_project_config
from lumen_argus.config.schema import Config
from lumen_argus.config.validation import _validate_config

log = logging.getLogger("argus.config")


def _parse_yaml(text: str) -> dict[str, Any]:
    """Parse YAML text into a dict using PyYAML safe_load."""
    result = yaml.safe_load(text)
    return result if isinstance(result, dict) else {}


def _warn(msg: str) -> None:
    """Log a config warning. Falls through to stderr via logging handlers."""
    log.warning("%s", msg)


_DEFAULT_CONFIG = """\
# lumen-argus configuration
# Docs: https://github.com/lumen-argus/lumen-argus
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
    action: alert
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
    - "sk-ant-api03-example-key-not-real"
  pii:
    - "*@example.com"
    - "*@test.local"
  paths:
    - "test/**"
    - "tests/**"
    - "fixtures/**"

# Notification channels (reconciled to DB on startup/SIGHUP)
# Manage via dashboard or define here for IaC. Requires published package.
# notifications:
#   - name: production-alerts
#     type: webhook
#     url: "https://hooks.slack.com/services/T00/B00/xxx"
#     events: [block, alert]
#     min_severity: high

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
    config_path: str | None = None,
    project_path: str | None = None,
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
            data = _parse_yaml(text)
            for w in _validate_config(data, str(proj)):
                _warn(w)
            _apply_project_config(config, data)
        except Exception as e:
            log.error("failed to parse %s: %s (using defaults)", proj, e)

    return config
