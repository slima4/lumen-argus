"""Action execution: dispatch block/alert/log actions."""

import json
from typing import Optional

from lumen_argus.models import ScanResult


def build_block_response(result: ScanResult) -> bytes:
    """Build a JSON error response body for blocked requests."""
    finding_summaries = []
    for f in result.findings:
        finding_summaries.append({
            "detector": f.detector,
            "type": f.type,
            "severity": f.severity,
            "location": f.location,
        })

    body = {
        "error": {
            "type": "request_blocked",
            "message": "lumen-argus blocked this request due to sensitive data detection.",
            "findings": finding_summaries,
        }
    }
    return json.dumps(body).encode("utf-8")


def should_forward(result: ScanResult) -> bool:
    """Return True if the request should be forwarded to upstream."""
    return result.action != "block"
