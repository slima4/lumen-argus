from __future__ import annotations

import itertools
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lumen_argus.async_proxy._server import AsyncArgusProxy

from lumen_argus.models import AuditEntry, ScanResult, SessionContext
from lumen_argus_core.time_utils import now_iso_ms

log = logging.getLogger("argus.proxy")

# Thread-safe request counter for the async proxy path.
_request_counter = itertools.count(1)


def _log_audit(
    server: "AsyncArgusProxy",
    request_id: int,
    path: str,
    provider: str,
    model: str,
    result: ScanResult,
    body_size: int,
    passed: bool,
    session: SessionContext | None = None,
) -> None:
    """Write audit log entry."""
    entry = AuditEntry(
        timestamp=now_iso_ms(),
        request_id=request_id,
        provider=provider,
        model=model,
        endpoint=path,
        action=result.action,
        findings=result.findings,
        scan_duration_ms=result.scan_duration_ms,
        request_size_bytes=body_size,
        passed=passed,
        account_id=session.account_id if session else "",
        api_key_hash=session.api_key_hash if session else "",
        session_id=session.session_id if session else "",
        device_id=session.device_id if session else "",
        source_ip=session.source_ip if session else "",
        working_directory=session.working_directory if session else "",
        git_branch=session.git_branch if session else "",
        os_platform=session.os_platform if session else "",
        client_name=session.client_name if session else "",
        client_version=session.client_version if session else "",
        raw_user_agent=session.raw_user_agent if session else "",
        api_format=session.api_format if session else "",
        sdk_name=session.sdk_name if session else "",
        sdk_version=session.sdk_version if session else "",
        runtime=session.runtime if session else "",
    )
    server.audit.log(entry)
