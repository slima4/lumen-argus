"""Build identity helpers — shared by proxy and agent ``/api/v1/build``.

The runtime-computed ``build_id`` (SHA256 of ``sys.executable``) is the
authoritative comparator for sidecar adoption: two processes with the
same ``build_id`` are running identical binary bytes. ``version``,
``git_commit``, and ``built_at`` are human fields for logs / UI /
support.

The per-service ``_build_info`` module is generated at PyInstaller build
time by ``scripts/generate_build_info.py``. It is absent in dev runs
(``python -m lumen_argus`` from source); ``get_build_info`` falls back to
a caller-supplied version and ``"unknown"`` for the other fields.
``build_id`` stays authoritative in either case because it always
reflects the bytes of ``sys.executable``.

See ``sidecar-build-identity-spec.md`` for the endpoint contract.
"""

from __future__ import annotations

import hashlib
import importlib
import logging
import sys
from functools import cache
from typing import Any

log = logging.getLogger("argus.build_info")

UNKNOWN = "unknown"
BUILD_ID_UNKNOWN = "sha256:" + UNKNOWN


@cache
def compute_build_id() -> str:
    """Return ``sha256:<hex>`` of the running binary (``sys.executable``).

    Cached after first call — the binary on disk may be replaced between
    runs, but within a single process the bytes are fixed. On OSError
    (unreadable executable) returns ``sha256:unknown`` and logs once.
    """
    try:
        digest = hashlib.sha256()
        with open(sys.executable, "rb") as f:
            while True:
                chunk = f.read(1 << 16)
                if not chunk:
                    break
                digest.update(chunk)
        return "sha256:" + digest.hexdigest()
    except OSError as exc:
        log.warning("compute_build_id: cannot read sys.executable=%s: %s", sys.executable, exc)
        return BUILD_ID_UNKNOWN


_SERVICE_MODULE = {
    "lumen-argus": "lumen_argus._build_info",
    "lumen-argus-agent": "lumen_argus_agent._build_info",
}


def get_build_info(service: str, version_fallback: str) -> dict[str, Any]:
    """Assemble the ``/api/v1/build`` payload for ``service``.

    Args:
        service: service name, e.g. ``"lumen-argus"`` or
            ``"lumen-argus-agent"``. Used as the ``service`` field and to
            locate the per-service ``_build_info`` module.
        version_fallback: version string to use when ``_build_info`` is
            absent (dev runs).

    Returns:
        ``{service, version, git_commit, build_id, built_at}``. Callers
        are responsible for adding a ``plugins`` key (proxy aggregates,
        agent always ``[]``).
    """
    version = version_fallback
    git_commit = UNKNOWN
    built_at = UNKNOWN

    module_name = _SERVICE_MODULE.get(service)
    if module_name is not None:
        try:
            mod = importlib.import_module(module_name)
        except ImportError:
            pass
        except Exception:
            log.warning("get_build_info: %s import failed; using fallbacks", module_name, exc_info=True)
        else:
            version = getattr(mod, "VERSION", version) or version
            git_commit = getattr(mod, "GIT_COMMIT", git_commit) or git_commit
            built_at = getattr(mod, "BUILT_AT", built_at) or built_at

    return {
        "service": service,
        "version": version,
        "git_commit": git_commit,
        "build_id": compute_build_id(),
        "built_at": built_at,
    }
