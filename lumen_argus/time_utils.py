"""Shared timestamp utilities."""

from datetime import datetime, timezone


def now_iso() -> str:
    """UTC timestamp in ISO 8601 format: 2026-03-25T12:00:00Z"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_iso_ms() -> str:
    """UTC timestamp with millisecond precision: 2026-03-25T12:00:00.123Z"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
