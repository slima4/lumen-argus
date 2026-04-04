"""Offline file scanner — reuses the detection pipeline without the proxy.

Used by the `lumen-argus scan` subcommand and as a git pre-commit hook.

Exit codes:
    0 — No findings
    1 — Findings with action "block" (should fail CI)
    2 — Findings with action "alert" only (CI can choose)
    3 — Findings with action "log" only (informational)
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
from dataclasses import replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore
    from lumen_argus.config import Config
    from lumen_argus.extensions import ExtensionRegistry

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.config import load_config
from lumen_argus.detectors.custom import CustomDetector
from lumen_argus.detectors.pii import PIIDetector
from lumen_argus.detectors.proprietary import ProprietaryDetector
from lumen_argus.detectors.secrets import SecretsDetector
from lumen_argus.models import Finding, ScanField

log = logging.getLogger("argus.scanner")

# Exit codes by action severity (highest wins).
# "redact" maps to "alert" in Community Edition (PolicyEngine downgrades it).
_EXIT_CODES = {"block": 1, "redact": 2, "alert": 2, "log": 3}


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate findings. Creates new objects to avoid mutation."""
    seen: dict[tuple[str, str, str], int] = {}
    first: dict[tuple[str, str, str], Finding] = {}
    for f in findings:
        key = (f.detector, f.type, f.matched_value)
        if key in seen:
            seen[key] += 1
        else:
            seen[key] = 1
            first[key] = f
    return [replace(first[k], count=c) for k, c in seen.items()]


def _build_detectors(config: Config) -> list[Any]:
    """Build detector list from config."""
    detectors: list[Any] = [
        SecretsDetector(entropy_threshold=config.entropy_threshold),
        PIIDetector(),
        ProprietaryDetector(),
    ]
    if config.custom_rules:
        detectors.append(CustomDetector(config.custom_rules))
    return detectors


def _resolve_exit_code(findings: list[Finding], config: Config) -> int:
    """Determine exit code from findings based on resolved actions.

    Uses the same action resolution as PolicyEngine: per-detector
    overrides, then default_action. Highest-severity action wins.
    """
    if not findings:
        return 0

    overrides: dict[str, str] = {}
    if config.secrets.action:
        overrides["secrets"] = config.secrets.action
    if config.pii.action:
        overrides["pii"] = config.pii.action
    if config.proprietary.action:
        overrides["proprietary"] = config.proprietary.action

    exit_code = 3  # log (lowest)
    for f in findings:
        action = f.action or overrides.get(f.detector, config.default_action)
        code = _EXIT_CODES.get(action, 3)
        if code < exit_code:
            exit_code = code  # lower code = higher severity

    return exit_code


def _load_db_allowlist(store: AnalyticsStore) -> dict[str, list[str]]:
    """Load allowlist entries from the database, grouped by list_type."""
    buckets: dict[str, list[str]] = {"secrets": [], "pii": [], "paths": []}
    try:
        for entry in store.list_enabled_allowlist_entries():
            lt = entry["list_type"]
            if lt in buckets:
                buckets[lt].append(entry["pattern"])
    except Exception as e:
        log.warning("failed to load DB allowlist entries: %s", e)
    return buckets


def _build_allowlist(
    config: Config, store: AnalyticsStore | None = None, extensions: ExtensionRegistry | None = None
) -> AllowlistMatcher:
    """Build allowlist from YAML config + DB entries."""
    secrets = list(config.allowlist.secrets)
    pii = list(config.allowlist.pii)
    paths = list(config.allowlist.paths)
    if store:
        db = _load_db_allowlist(store)
        secrets.extend(db["secrets"])
        pii.extend(db["pii"])
        paths.extend(db["paths"])
    # Use custom factory if registered (Enterprise: Hyperscan)
    if extensions:
        factory = extensions.get_allowlist_matcher_factory()
        if factory:
            try:
                result: AllowlistMatcher = factory(secrets=secrets, pii=pii, paths=paths)
                return result
            except Exception as e:
                log.warning("allowlist matcher factory failed, using default: %s", e)
    return AllowlistMatcher(secrets=secrets, pii=pii, paths=paths)


def scan_text(
    text: str,
    config_path: str | None = None,
    output_format: str = "text",
) -> int:
    """Scan text for secrets/PII/proprietary content.

    Returns:
        Exit code: 0=clean, 1=block findings, 2=alert/redact only, 3=log only.
    """
    config = load_config(config_path=config_path)
    allowlist = _build_allowlist(config)
    detectors = _build_detectors(config)

    fields = [ScanField(path="stdin", text=text)]
    all_findings: list[Finding] = []
    for det in detectors:
        all_findings.extend(det.scan(fields, allowlist))

    findings = _deduplicate(all_findings)

    if not findings:
        if output_format == "json":
            print(json.dumps({"status": "clean", "findings": []}))
        return 0

    exit_code = _resolve_exit_code(findings, config)

    if output_format == "json":
        print(
            json.dumps(
                {
                    "status": "findings",
                    "count": len(findings),
                    "exit_code": exit_code,
                    "findings": [
                        {
                            "detector": f.detector,
                            "type": f.type,
                            "severity": f.severity,
                            "location": f.location,
                            "count": f.count,
                        }
                        for f in findings
                    ],
                }
            )
        )
    else:
        print("lumen-argus: %d finding(s) detected" % len(findings), file=sys.stderr)
        for f in findings:
            count_str = " (\u00d7%d)" % f.count if f.count > 1 else ""
            print(
                "  [%s] %s: %s%s" % (f.severity.upper(), f.detector, f.type, count_str),
                file=sys.stderr,
            )

    return exit_code


def scan_files(
    files: list[str],
    config_path: str | None = None,
    output_format: str = "text",
    baseline_path: str | None = None,
    create_baseline_path: str | None = None,
) -> int:
    """Scan one or more files.

    Returns:
        Exit code: 0=clean, 1=block findings, 2=alert only, 3=log only.
    """
    from lumen_argus.baseline import filter_baseline, load_baseline, save_baseline

    config = load_config(config_path=config_path)
    allowlist = _build_allowlist(config)
    detectors = _build_detectors(config)
    baseline = load_baseline(baseline_path) if baseline_path else set()
    all_file_findings = {}  # type: dict[str, list[Finding]]
    exit_code = 0

    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except (OSError, IOError) as e:
            print("lumen-argus: cannot read %s: %s" % (filepath, e), file=sys.stderr)
            continue

        if allowlist.is_allowed_path(filepath):
            continue

        fields = [ScanField(path=filepath, text=text, source_filename=filepath)]
        all_findings: list[Finding] = []
        for det in detectors:
            all_findings.extend(det.scan(fields, allowlist))

        findings = _deduplicate(all_findings)

        # Collect all findings for create-baseline before filtering
        if create_baseline_path and findings:
            all_file_findings[filepath] = list(findings)

        # Filter out baseline findings
        if baseline:
            findings = filter_baseline(findings, filepath, baseline)

        if findings:
            file_exit = _resolve_exit_code(findings, config)
            if exit_code == 0 or file_exit < exit_code:
                exit_code = file_exit

            if output_format == "json":
                print(
                    json.dumps(
                        {
                            "file": filepath,
                            "count": len(findings),
                            "exit_code": file_exit,
                            "findings": [
                                {
                                    "detector": f.detector,
                                    "type": f.type,
                                    "severity": f.severity,
                                    "location": f.location,
                                    "count": f.count,
                                }
                                for f in findings
                            ],
                        }
                    )
                )
            else:
                print("lumen-argus: %s — %d finding(s)" % (filepath, len(findings)), file=sys.stderr)
                for f in findings:
                    count_str = " (\u00d7%d)" % f.count if f.count > 1 else ""
                    print(
                        "  [%s] %s: %s%s" % (f.severity.upper(), f.detector, f.type, count_str),
                        file=sys.stderr,
                    )

    if create_baseline_path:
        save_baseline(create_baseline_path, all_file_findings)

    return exit_code


# Unified diff header: "+++ b/path"
_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$")
_BINARY_FILE_RE = re.compile(r"^Binary files [^\n]+ and b/([^\n]+) differ$")


def _parse_diff(diff_text: str) -> dict[str, str]:
    """Parse unified diff into {filename: added_lines_text}.

    Only collects added lines (lines starting with '+', excluding
    the '+++ b/...' header). Deleted lines are ignored since secrets
    in removed code are no longer a risk.
    """
    files = {}  # type: dict[str, str]
    current_file = None
    lines: list[str] = []

    for line in diff_text.splitlines():
        m = _DIFF_FILE_RE.match(line)
        if m:
            if current_file and lines:
                files[current_file] = "\n".join(lines)
            current_file = m.group(1)
            lines = []
            continue
        bm = _BINARY_FILE_RE.match(line)
        if bm:
            print("lumen-argus: skipped binary file %s" % bm.group(1), file=sys.stderr)
            continue
        if current_file and line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])  # strip the leading '+'

    if current_file and lines:
        files[current_file] = "\n".join(lines)

    return files


def scan_diff(
    ref: str | None = None,
    config_path: str | None = None,
    output_format: str = "text",
    baseline_path: str | None = None,
) -> int:
    """Scan git diff for secrets/PII/proprietary content.

    Args:
        ref: Git ref to diff against (e.g. 'main', 'HEAD~3').
             If None, scans staged changes (git diff --cached).
        config_path: Path to config file.
        output_format: 'text' or 'json'.
        baseline_path: Path to baseline file (findings to ignore).

    Returns:
        Exit code: 0=clean, 1=block findings, 2=alert/redact only, 3=log only.
    """
    cmd = ["git", "diff", "--cached", "-U0"]
    if ref:
        cmd = ["git", "diff", ref, "-U0"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        print("lumen-argus: git not found — --diff requires git", file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired:
        print("lumen-argus: git diff timed out", file=sys.stderr)
        return 1

    if result.returncode != 0:
        stderr = result.stderr.strip()
        if stderr:
            print("lumen-argus: git diff failed: %s" % stderr, file=sys.stderr)
        return 1

    diff_text = result.stdout
    if not diff_text.strip():
        if output_format == "json":
            print(json.dumps({"status": "clean", "findings": []}))
        return 0

    file_texts = _parse_diff(diff_text)
    if not file_texts:
        if output_format == "json":
            print(json.dumps({"status": "clean", "findings": []}))
        return 0

    from lumen_argus.baseline import filter_baseline, load_baseline

    config = load_config(config_path=config_path)
    allowlist = _build_allowlist(config)
    detectors = _build_detectors(config)
    baseline = load_baseline(baseline_path) if baseline_path else set()
    exit_code = 0

    for filepath, text in file_texts.items():
        if allowlist.is_allowed_path(filepath):
            continue

        fields = [ScanField(path=filepath, text=text, source_filename=filepath)]
        all_findings: list[Finding] = []
        for det in detectors:
            all_findings.extend(det.scan(fields, allowlist))

        findings = _deduplicate(all_findings)
        if baseline:
            findings = filter_baseline(findings, filepath, baseline)

        if findings:
            file_exit = _resolve_exit_code(findings, config)
            if exit_code == 0 or file_exit < exit_code:
                exit_code = file_exit

            if output_format == "json":
                print(
                    json.dumps(
                        {
                            "file": filepath,
                            "count": len(findings),
                            "exit_code": file_exit,
                            "findings": [
                                {
                                    "detector": f.detector,
                                    "type": f.type,
                                    "severity": f.severity,
                                    "location": f.location,
                                    "count": f.count,
                                }
                                for f in findings
                            ],
                        }
                    )
                )
            else:
                print("lumen-argus: %s — %d finding(s)" % (filepath, len(findings)), file=sys.stderr)
                for f in findings:
                    count_str = " (\u00d7%d)" % f.count if f.count > 1 else ""
                    print(
                        "  [%s] %s: %s%s" % (f.severity.upper(), f.detector, f.type, count_str),
                        file=sys.stderr,
                    )

    return exit_code
