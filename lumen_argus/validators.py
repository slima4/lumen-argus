"""Shared validation functions for PII and financial data.

Used by both the hardcoded PII detector (patterns/pii_patterns.py) and
the DB-backed RulesDetector (detectors/rules.py). Centralizing prevents
drift between the two detection paths.
"""


def validate_ssn(value: str) -> bool:
    """Validate US SSN: not 000/666/900+ area, not 00 group, not 0000 serial."""
    digits = value.replace("-", "")
    if len(digits) != 9:
        return False
    area, group, serial = int(digits[:3]), int(digits[3:5]), int(digits[5:])
    if area == 0 or area == 666 or area >= 900:
        return False
    return group != 0 and serial != 0


def validate_luhn(value: str) -> bool:
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


def validate_ip_not_private(value: str) -> bool:
    """Return True only for non-private, non-special IPv4 addresses."""
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
    if first in (0, 127):  # 0.0.0.0/8, loopback
        return False
    if first == 10:  # 10.0.0.0/8
        return False
    if first == 172 and 16 <= octets[1] <= 31:  # 172.16.0.0/12
        return False
    if first == 192 and octets[1] == 168:  # 192.168.0.0/16
        return False
    if first == 169 and octets[1] == 254:  # link-local
        return False
    return True


def validate_iban(value: str) -> bool:
    """Validate IBAN using MOD-97 checksum (ISO 13616)."""
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
