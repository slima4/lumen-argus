"""Built-in PII detection patterns with validation."""

import re
from typing import Callable, NamedTuple, Optional

from lumen_argus.validators import validate_iban, validate_ip_not_private, validate_luhn, validate_ssn


class PIIPattern(NamedTuple):
    name: str
    pattern: "re.Pattern[str]"
    severity: str
    validator: Optional[Callable[[str], bool]]  # None = match always counts


# Local aliases for backward compatibility with existing PII_PATTERNS references
_validate_ssn = validate_ssn
_luhn_check = validate_luhn
_exclude_private_ips = validate_ip_not_private
_validate_iban = validate_iban


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
        _validate_iban,
    ),
    PIIPattern(
        "passport_us",
        re.compile(r"\b[A-Z]\d{8}\b"),
        "info",
        None,
    ),
)
