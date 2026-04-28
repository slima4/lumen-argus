"""Logging helpers shared across the proxy."""

from __future__ import annotations

import logging

log = logging.getLogger("argus.proxy")


def log_hook_fail_open(what: str, *, request_id: int | None = None) -> None:
    """Emit ``"<what> failed (fail-open)"`` at ERROR with the active traceback.

    Always paired with a ``try/except Exception:`` that swallows the error and
    continues with the original (un-modified) artifact. Must only be called
    from inside the ``except`` block so ``exc_info=True`` captures the live
    exception.
    """
    if request_id is not None:
        log.error("#%d %s failed (fail-open)", request_id, what, exc_info=True)
    else:
        log.error("%s failed (fail-open)", what, exc_info=True)
