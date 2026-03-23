"""DB-backed rules detector with Aho-Corasick pre-filtering.

Loads compiled regex patterns from the rules DB table. Runs alongside
(or eventually replaces) the hardcoded SecretsDetector and PIIDetector.

Performance layers:
1. Aho-Corasick pre-filter: O(n) single pass narrows 1,700+ rules to ~15 candidates
2. Early termination: stop after first match when action is "block"
3. Hot-first ordering: sort rules by hit_count DESC for faster common matches

License-aware: rules with tier='pro' are skipped when the license
checker reports invalid/expired.
"""

import logging
import re
import threading
import time
from typing import List

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.detectors import BaseDetector
from lumen_argus.detectors.accelerator import AhoCorasickAccelerator
from lumen_argus.models import Finding, ScanField

log = logging.getLogger("argus.detectors.rules")

# Registry of named validator functions. Validators return True if
# the match is valid. Referenced by name in the rules DB.
_VALIDATORS = {}

# Flush hit counts to DB every 60 seconds
_HIT_COUNT_FLUSH_INTERVAL = 60


def register_validator(name, fn):
    """Register a named validator function."""
    _VALIDATORS[name] = fn


def _validate_ssn(value):
    digits = value.replace("-", "")
    if len(digits) != 9:
        return False
    area, group, serial = int(digits[:3]), int(digits[3:5]), int(digits[5:])
    if area == 0 or area == 666 or area >= 900:
        return False
    return group != 0 and serial != 0


def _luhn_check(value):
    digits = [int(d) for d in value if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _exclude_private_ips(value):
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if any(o < 0 or o > 255 for o in octets):
        return False
    first = octets[0]
    if first in (0, 127):
        return False
    if first == 10:
        return False
    if first == 172 and 16 <= octets[1] <= 31:
        return False
    if first == 192 and octets[1] == 168:
        return False
    if first == 169 and octets[1] == 254:
        return False
    return True


def _validate_iban(value):
    cleaned = value.replace(" ", "").upper()
    if len(cleaned) < 5 or len(cleaned) > 34:
        return False
    rearranged = cleaned[4:] + cleaned[:4]
    digits = []
    for c in rearranged:
        if c.isdigit():
            digits.append(c)
        elif c.isalpha():
            digits.append(str(ord(c) - ord("A") + 10))
        else:
            return False
    return int("".join(digits)) % 97 == 1


# Register built-in validators
register_validator("ssn_range", _validate_ssn)
register_validator("luhn", _luhn_check)
register_validator("exclude_private_ips", _exclude_private_ips)
register_validator("iban_mod97", _validate_iban)


class RulesDetector(BaseDetector):
    """Unified detector that runs all DB-backed rules.

    Loads rules from the analytics store, compiles regex patterns,
    and runs them against scan fields. License-aware for Pro rules.

    Performance:
    - Aho-Corasick pre-filter reduces candidate rules per field by >95%
    - Hot-first ordering puts frequent matches first
    - Early termination stops on first match for block actions
    - In-memory hit count accumulation with periodic batch flush
    """

    def __init__(self, store=None, license_checker=None, metrics_collector=None):
        self._store = store
        self._license = license_checker
        self._metrics = metrics_collector
        self._compiled_rules = []  # type: list
        self._accelerator = AhoCorasickAccelerator()
        # In-memory hit count accumulation: {rule_name: count}
        self._hit_counts = {}  # type: dict
        self._hit_counts_lock = threading.Lock()
        self._last_flush = time.monotonic()
        if store:
            self.reload()

    def reload(self):
        """Reload rules from DB, compile patterns, and rebuild accelerator."""
        if not self._store:
            return
        # Flush pending hit counts before reload
        self._flush_hit_counts()

        rules = self._store.get_active_rules()
        compiled = []
        for r in rules:
            if r["tier"] == "pro":
                if self._license is None or not self._license.is_valid():
                    continue
            try:
                pattern = re.compile(r["pattern"])
            except re.error:
                log.warning("rule '%s': invalid regex, skipping", r["name"])
                continue
            validator = None
            if r.get("validator"):
                validator = _VALIDATORS.get(r["validator"])
                if validator is None:
                    log.debug("rule '%s': unknown validator '%s'", r["name"], r["validator"])
            compiled.append(
                {
                    "name": r["name"],
                    "compiled": pattern,
                    "detector": r["detector"],
                    "severity": r["severity"],
                    "action": r.get("action", ""),
                    "validator": validator,
                    "hit_count": r.get("hit_count", 0),
                }
            )

        # Hot-first ordering: rules with more hits are evaluated first
        compiled.sort(key=lambda r: r["hit_count"], reverse=True)

        # Build new accelerator, then swap both atomically.
        # scan() snapshots both — they must be consistent.
        new_acc = AhoCorasickAccelerator()
        new_acc.build(compiled)
        self._accelerator = new_acc
        self._compiled_rules = compiled
        log.info(
            "rules detector: loaded %d rules (accelerator: %s)",
            len(compiled),
            "enabled" if self._accelerator.available else "disabled",
        )

    def _flush_hit_counts(self):
        """Flush accumulated hit counts to DB in a single batch."""
        with self._hit_counts_lock:
            if not self._hit_counts:
                return
            snapshot = self._hit_counts
            self._hit_counts = {}
            self._last_flush = time.monotonic()

        if not self._store:
            return

        try:
            with self._store._lock:
                conn = self._store._connect()
                for rule_name, count in snapshot.items():
                    conn.execute(
                        "UPDATE rules SET hit_count = hit_count + ? WHERE name = ?",
                        (count, rule_name),
                    )
                conn.commit()
            log.debug("hit counts flushed: %d rules updated", len(snapshot))
        except Exception as e:
            log.warning("hit count flush failed: %s", e)

    def _record_hit(self, rule_name):
        """Accumulate a hit in memory. Flush periodically."""
        with self._hit_counts_lock:
            self._hit_counts[rule_name] = self._hit_counts.get(rule_name, 0) + 1

        # Check if flush is due (outside lock to avoid holding it during I/O)
        if time.monotonic() - self._last_flush >= _HIT_COUNT_FLUSH_INTERVAL:
            self._flush_hit_counts()

    def on_rules_changed(self, change_type, rule_name=None):
        """Handle rule changes from store callback.

        "bulk": full reload (import). "delete"/"create"/"update": incremental.
        Incremental avoids recompiling all rules for a single-rule change.

        Thread safety: all mutations create a new list and assign atomically
        (single reference swap under CPython GIL). Never mutate in-place —
        a scan thread may be iterating the old list concurrently.
        """
        if change_type == "bulk":
            self.reload()
            return
        if rule_name is None:
            log.warning("on_rules_changed: rule_name required for %s, falling back to reload", change_type)
            self.reload()
            return
        if change_type == "delete":
            new_rules = [r for r in self._compiled_rules if r["name"] != rule_name]
            new_acc = AhoCorasickAccelerator()
            new_acc.build(new_rules)
            self._accelerator = new_acc
            self._compiled_rules = new_rules
            return
        # "create" or "update" — fetch and compile just this one rule
        if not self._store:
            return
        rule = self._store.get_rule_by_name(rule_name)
        if rule is None or not rule.get("enabled"):
            new_rules = [r for r in self._compiled_rules if r["name"] != rule_name]
            new_acc = AhoCorasickAccelerator()
            new_acc.build(new_rules)
            self._accelerator = new_acc
            self._compiled_rules = new_rules
            return
        if rule.get("tier") == "pro":
            if self._license is None or not self._license.is_valid():
                new_rules = [r for r in self._compiled_rules if r["name"] != rule_name]
                new_acc = AhoCorasickAccelerator()
                new_acc.build(new_rules)
                self._accelerator = new_acc
                self._compiled_rules = new_rules
                return
        try:
            compiled = re.compile(rule["pattern"])
        except re.error:
            return
        validator = None
        if rule.get("validator"):
            validator = _VALIDATORS.get(rule["validator"])
        new_entry = {
            "name": rule["name"],
            "compiled": compiled,
            "detector": rule["detector"],
            "severity": rule["severity"],
            "action": rule.get("action", ""),
            "validator": validator,
            "hit_count": rule.get("hit_count", 0),
        }
        # Build new list: replace existing or append. Creates a new list
        # object for atomic swap — never mutate in-place during concurrent iteration.
        replaced = False
        new_list = []
        for r in self._compiled_rules:
            if r["name"] == rule_name:
                new_list.append(new_entry)
                replaced = True
            else:
                new_list.append(r)
        if not replaced:
            new_list.append(new_entry)
        new_acc = AhoCorasickAccelerator()
        new_acc.build(new_list)
        self._accelerator = new_acc
        self._compiled_rules = new_list

    def scan(self, fields: List[ScanField], allowlist: AllowlistMatcher) -> List[Finding]:
        """Scan fields against compiled rules with Aho-Corasick pre-filtering.

        Performance path:
        1. Pre-filter: Aho-Corasick narrows candidates per field
        2. Hot-first: rules sorted by hit_count DESC (set at reload)
        3. Early termination: stop on first match for block action
        """
        findings = []
        compiled_rules = self._compiled_rules  # snapshot for thread safety
        accelerator = self._accelerator
        metrics = self._metrics

        for field in fields:
            # Pre-filter: get candidate rule indices for this field's text
            candidates = accelerator.filter(field.text)

            if log.isEnabledFor(logging.DEBUG):
                ratio = accelerator.filter_ratio(candidates)
                log.debug(
                    "pre-filter: %d rules -> %d candidates (%.1f%% filtered) for %s",
                    len(compiled_rules),
                    len(candidates),
                    ratio * 100,
                    field.path,
                )

            for idx in candidates:
                if idx >= len(compiled_rules):
                    continue
                rule = compiled_rules[idx]

                t0 = time.monotonic() if metrics else 0

                for match in rule["compiled"].finditer(field.text):
                    # Prefer first capture group (the secret value) over
                    # full match (which may include keyword prefix like "password=")
                    matched = (match.group(1) if match.lastindex else None) or match.group(0)
                    if not matched:
                        continue
                    # Run validator if present
                    if rule["validator"] and not rule["validator"](matched):
                        continue
                    # Check allowlist
                    if rule["detector"] == "secrets" and allowlist.is_allowed_secret(matched):
                        continue
                    if rule["detector"] == "pii" and allowlist.is_allowed_pii(matched):
                        continue
                    preview = matched[:4] + "****" if len(matched) > 4 else "****"
                    findings.append(
                        Finding(
                            detector=rule["detector"],
                            type=rule["name"],
                            severity=rule["severity"],
                            location=field.path,
                            value_preview=preview,
                            matched_value=matched,
                            action=rule["action"],
                        )
                    )
                    # Record hit for hot-first ordering
                    self._record_hit(rule["name"])

                    # Record metrics for Pro performance dashboard
                    if metrics:
                        elapsed_ms = (time.monotonic() - t0) * 1000
                        try:
                            metrics.record(rule["name"], elapsed_ms)
                        except Exception:
                            pass

                    # Early termination: if this rule's action is block,
                    # no need to check remaining rules for this field
                    if rule["action"] == "block":
                        log.debug(
                            "early termination: block after match on '%s'",
                            rule["name"],
                        )
                        break  # break inner finditer loop

                else:
                    # finditer loop completed without break — continue to next rule
                    continue
                # finditer broke (block match) — break out of candidates loop too
                break

        return findings
