"""Rules command — import, export, list, and validate detection rules.

Changes when: rules management workflow or display format changes.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore


def run_rules(args: argparse.Namespace) -> None:
    """Execute the 'rules' subcommand."""
    from lumen_argus.analytics.store import AnalyticsStore
    from lumen_argus.config import load_config as _load_config

    config_path = getattr(args, "config", None)
    config = _load_config(config_path=config_path)
    store = AnalyticsStore(db_path=config.analytics.db_path)

    if args.rules_command == "import":
        _rules_import(args, store)
    elif args.rules_command == "export":
        _rules_export(args, store)
    elif args.rules_command == "list":
        _rules_list(args, store)
    elif args.rules_command == "validate":
        _rules_validate(args)


def _rules_import(args: argparse.Namespace, store: AnalyticsStore) -> None:
    """Import rules from bundled JSON into DB."""
    from lumen_argus.config_loader import load_rules_bundle, trigger_auto_analysis

    if args.pro:
        try:
            from lumen_argus_pro.license import get_license  # type: ignore[import-not-found]

            lic = get_license()
            if not lic.is_valid:
                print(
                    "lumen-argus: Pro license required. Activate with: lumen-argus license activate",
                    file=sys.stderr,
                )
                sys.exit(1)
        except ImportError:
            print("lumen-argus: lumen-argus-pro not installed", file=sys.stderr)
            sys.exit(1)
    if args.dry_run:
        rules, version, tier = load_rules_bundle(path=args.file, pro=args.pro)
        print("lumen-argus: dry run — %d %s rules (v%s)" % (len(rules), tier, version))
        return
    rules, version, tier = load_rules_bundle(path=args.file, pro=args.pro)
    print("lumen-argus: importing %s rules v%s" % (tier, version))
    result = store.import_rules(rules, tier=tier, force=args.force)
    print(
        "  %d rules imported (%d new, %d updated, %d skipped)"
        % (result["created"] + result["updated"], result["created"], result["updated"], result["skipped"])
    )
    total = store.get_rules_count()
    print("  total: %d rules in DB" % total)
    trigger_auto_analysis(store, None)


def _rules_export(args: argparse.Namespace, store: AnalyticsStore) -> None:
    """Export rules as JSON."""
    rules = store.export_rules(tier=args.tier, detector=args.detector)
    bundle = {"version": "0.4.0", "tier": args.tier or "all", "rules": rules}
    print(json.dumps(bundle, indent=2, default=str))


def _rules_list(args: argparse.Namespace, store: AnalyticsStore) -> None:
    """List loaded rules."""
    rules = store.export_rules(tier=args.tier, detector=args.detector)
    if not rules:
        print("lumen-argus: no rules found. Run 'lumen-argus rules import' first.")
        return
    print("\n  %-30s %-10s %-10s %-8s %-12s %s" % ("NAME", "DETECTOR", "SEVERITY", "ACTION", "TIER", "ENABLED"))
    print("  " + "-" * 90)
    for r in rules:
        print(
            "  %-30s %-10s %-10s %-8s %-12s %s"
            % (
                r["name"][:30],
                r["detector"],
                r["severity"],
                r.get("action") or "(default)",
                r["tier"],
                "yes" if r["enabled"] else "no",
            )
        )
    stats = store.get_rule_stats()
    by_tier = ", ".join("%d %s" % (v, k) for k, v in stats["by_tier"].items())
    print("\n  %d rules (%s)\n" % (stats["total"], by_tier))


def _rules_validate(args: argparse.Namespace) -> None:
    """Validate rules JSON file."""
    import re as re_mod

    try:
        with open(args.file, encoding="utf-8") as f:
            bundle = json.load(f)
    except FileNotFoundError:
        print("lumen-argus: file not found: %s" % args.file, file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print("lumen-argus: invalid JSON in %s: %s" % (args.file, e), file=sys.stderr)
        sys.exit(1)
    rules = bundle.get("rules", [])
    errors = 0
    for i, r in enumerate(rules):
        name = r.get("name", "rule_%d" % i)
        pattern = r.get("pattern", "")
        if not name:
            print("  ERROR: rule %d — missing name" % i)
            errors += 1
        if not pattern:
            print("  ERROR: rule '%s' — missing pattern" % name)
            errors += 1
        else:
            try:
                re_mod.compile(pattern)
            except re_mod.error as e:
                print("  ERROR: rule '%s' — invalid regex: %s" % (name, e))
                errors += 1
    if errors:
        print("\n  %d rules validated, %d errors" % (len(rules), errors))
        sys.exit(1)
    else:
        print("  %d rules validated, 0 errors" % len(rules))
