"""Built-in PII detection patterns with validation."""

import re
from typing import Callable, NamedTuple, Optional


class PIIPattern(NamedTuple):
    name: str
    pattern: "re.Pattern[str]"
    severity: str
    validator: Optional[Callable[[str], bool]]  # None = match always counts


def _validate_ssn(value: str) -> bool:
    """Validate US SSN: not 000/666/900+ area, not 00 group, not 0000 serial."""
    digits = value.replace("-", "")
    if len(digits) != 9:
        return False
    area, group, serial = int(digits[:3]), int(digits[3:5]), int(digits[5:])
    if area == 0 or area == 666 or area >= 900:
        return False
    if group == 0 or serial == 0:
        return False
    return True


def _luhn_check(value: str) -> bool:
    """Luhn algorithm for credit card validation."""
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


def _exclude_private_ips(value: str) -> bool:
    """Return True only for non-private, non-special IP addresses."""
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
    # Exclude loopback, private, link-local, and special ranges
    if first == 127:  # loopback
        return False
    if first == 10:  # 10.0.0.0/8
        return False
    if first == 172 and 16 <= octets[1] <= 31:  # 172.16.0.0/12
        return False
    if first == 192 and octets[1] == 168:  # 192.168.0.0/16
        return False
    if first == 169 and octets[1] == 254:  # link-local
        return False
    if first == 0:  # 0.0.0.0/8
        return False
    return True


PII_PATTERNS = (
    PIIPattern(
        "email",
        re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        "warning",
        None,
    ),
    PIIPattern(
        "ssn",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "critical",
        _validate_ssn,
    ),
    PIIPattern(
        "credit_card",
        re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),
        "critical",
        _luhn_check,
    ),
    PIIPattern(
        "phone_us",
        re.compile(r"\b(?:\+1)?[\s.\-]?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b"),
        "warning",
        None,
    ),
    PIIPattern(
        "phone_intl",
        re.compile(r"\+\d{1,3}[\s.\-]?\d{4,14}"),
        "info",
        None,
    ),
    PIIPattern(
        "ip_address",
        re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
        "info",
        _exclude_private_ips,
    ),
    PIIPattern(
        "iban",
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),
        "warning",
        None,
    ),
    PIIPattern(
        "passport_us",
        re.compile(r"\b[A-Z]\d{8}\b"),
        "info",
        None,
    ),
)
