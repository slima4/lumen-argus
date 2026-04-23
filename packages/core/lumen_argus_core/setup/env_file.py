"""``~/.lumen-argus/env`` body management.

The env file is the single artefact every shell sources to route AI
tools through the proxy. This module owns reading, writing (atomic),
locking, and header-mode detection. Body formatting lives in
:mod:`lumen_argus_core.env_template`; the shell-profile block that
sources this file lives in :mod:`lumen_argus_core.setup.source_block`.
"""

from __future__ import annotations

import logging
import os
import re
import tempfile

from lumen_argus_core.env_template import ManagedBy, parse_header_managed_by, render_body
from lumen_argus_core.setup._models import SetupChange
from lumen_argus_core.setup._paths import _ARGUS_DIR, _ENV_FILE, _ENV_LOCK, MANAGED_TAG
from lumen_argus_core.setup.manifest import _detect_shell_profile
from lumen_argus_core.setup.source_block import install_source_block
from lumen_argus_core.time_utils import now_iso

log = logging.getLogger("argus.setup.env_file")

# Underscore-prefixed names are re-exported here explicitly because
# :mod:`setup.protection` and :mod:`setup.orchestrator` reach them via the module handle (e.g.
# ``_env_file._ENV_FILE``) so tests only patch one location.
__all__ = [
    "_ARGUS_DIR",
    "_ENV_FILE",
    "_env_file_lock",
    "_read_managed_by_from_disk",
    "add_env_to_env_file",
    "add_env_to_shell_profile",
    "read_env_file",
    "write_env_file",
]


class _env_file_lock:
    """Context manager for exclusive access to the env file.

    ``fcntl.flock`` on Unix prevents concurrent read-modify-write races
    between the CLI and the tray app. No-op on Windows (the env file is
    Unix-only anyway).
    """

    def __init__(self) -> None:
        self._fd: int | None = None

    def __enter__(self) -> "_env_file_lock":
        os.makedirs(_ARGUS_DIR, mode=0o700, exist_ok=True)
        try:
            import fcntl

            self._fd = os.open(_ENV_LOCK, os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(self._fd, fcntl.LOCK_EX)
        except ImportError:
            # Windows — fcntl not available, lock is a no-op by design.
            self._fd = None
        except OSError as e:
            # Disk full / EPERM / stale NFS mount — the race this lock
            # prevents (CLI vs tray concurrent write) is exactly what the
            # user should know about rather than have silently downgraded.
            log.warning("env file lock unavailable (%s); proceeding without exclusive access", e)
            self._fd = None
        return self

    def __exit__(self, *args: object) -> None:
        if self._fd is not None:
            try:
                import fcntl

                fcntl.flock(self._fd, fcntl.LOCK_UN)
            except (ImportError, OSError) as e:
                log.debug("env file unlock failed (%s); file descriptor closed regardless", e)
            os.close(self._fd)
            self._fd = None


# Parser for managed env file lines. Accepts two shapes:
#   export VAR=value  # lumen-argus:managed client=<id>   (canonical)
#   export VAR='value'  # lumen-argus:managed             (orphan — no client tag)
#
# Orphans surface because third-party writers (e.g. an older tray app build)
# can append to ~/.lumen-argus/env directly without going through
# ``add_env_to_env_file``. ``protection_status`` still needs to see them, and
# ``add_env_to_env_file`` needs to evict them when a canonical write targets
# the same variable.
_MANAGED_LINE_RE = re.compile(r"^export\s+(\w+)=(\S+)\s+#\s+lumen-argus:managed(?:\s+client=(\S+))?\s*$")


def _strip_quotes(value: str) -> str:
    """Strip a single matching pair of surrounding single or double quotes."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def read_env_file() -> list[tuple[str, str, str]]:
    """Read the env file and return (var_name, value, client_id) tuples.

    Values with surrounding single or double quotes are unquoted. Lines
    written without a ``client=<id>`` suffix surface with an empty
    client_id — orphans that no known client owns.
    """
    if not os.path.isfile(_ENV_FILE):
        return []
    entries: list[tuple[str, str, str]] = []
    try:
        with open(_ENV_FILE, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                m = _MANAGED_LINE_RE.match(line)
                if not m:
                    continue
                var_name = m.group(1)
                value = _strip_quotes(m.group(2))
                client_id = m.group(3) or ""
                entries.append((var_name, value, client_id))
    except OSError as e:
        log.warning("could not read env file: %s", e)
    return entries


def _read_managed_by_from_disk() -> ManagedBy | None:
    """Return the mode recorded in the current env file, if any.

    The first line carries the header (see :mod:`env_template`); we stop
    reading after one line.
    """
    if not os.path.isfile(_ENV_FILE):
        return None
    try:
        with open(_ENV_FILE, "r", encoding="utf-8") as f:
            return parse_header_managed_by(f.readline())
    except OSError as e:
        log.warning("could not read env file header: %s", e)
        return None


def write_env_file(
    entries: list[tuple[str, str, str]],
    *,
    managed_by: ManagedBy | None = None,
) -> None:
    """Write env vars to ``~/.lumen-argus/env`` atomically.

    Write-to-temp-then-rename prevents corruption on SIGKILL/OOM. File
    gets ``0o600`` because it is sourced by the shell — a writable env
    file is an arbitrary-code-execution vector.

    Mode is sticky: when the caller does not specify ``managed_by``, the
    mode recorded on the existing file is preserved so that low-level
    mutators (``add_env_to_env_file``) never silently strip the liveness
    guard from an enrolled machine. Fresh machine with no existing file
    falls back to :attr:`ManagedBy.CLI`.
    """
    if managed_by is None:
        managed_by = _read_managed_by_from_disk() or ManagedBy.CLI

    os.makedirs(_ARGUS_DIR, mode=0o700, exist_ok=True)
    body = render_body(entries, MANAGED_TAG, managed_by=managed_by)
    try:
        fd, tmp_path = tempfile.mkstemp(dir=_ARGUS_DIR, prefix=".env.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(body)
            os.chmod(tmp_path, 0o600)
            os.rename(tmp_path, _ENV_FILE)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        log.info("env file written (%s): %d var(s)", managed_by.value, len(entries))
    except OSError as e:
        log.error("could not write env file (%s): %s", managed_by.value, e, exc_info=True)


def add_env_to_env_file(
    var_name: str,
    value: str,
    client_id: str,
    dry_run: bool = False,
) -> SetupChange | None:
    """Add an env var to ``~/.lumen-argus/env``.

    File-level lock prevents concurrent read-modify-write races between
    CLI and tray app. Returns a :class:`SetupChange` on success, ``None``
    if the requested entry was already present.
    """
    export_line = "export %s=%s  %s client=%s" % (var_name, value, MANAGED_TAG, client_id)

    if dry_run:
        existing = read_env_file()
        for ev, val, cid in existing:
            if ev == var_name and val == value and cid == client_id:
                return None
        log.info("[dry-run] would add to env file: %s", export_line)
        return SetupChange(
            timestamp=now_iso(),
            client_id=client_id,
            method="env_file",
            file=_ENV_FILE,
            detail=export_line,
        )

    with _env_file_lock():
        existing = read_env_file()

        for ev, val, cid in existing:
            if ev == var_name and val == value and cid == client_id:
                log.info("already in env file: %s=%s (client=%s)", var_name, value, client_id)
                return None

        # Remove any existing entry for this var+client before adding. Also
        # evict orphan entries (cid == "") for the same var — unattributable
        # lines left by a non-conformant writer. Letting them coexist
        # produces duplicate ``export VAR=...`` lines where only the last
        # one wins in the shell, masking the value we just set.
        filtered = [
            (ev, val, cid) for ev, val, cid in existing if not (ev == var_name and (cid == client_id or cid == ""))
        ]
        evicted_orphans = sum(1 for ev, _, cid in existing if ev == var_name and cid == "")
        if evicted_orphans:
            log.info(
                "evicted %d orphan env file entr%s for %s (unowned, non-conformant writer)",
                evicted_orphans,
                "y" if evicted_orphans == 1 else "ies",
                var_name,
            )
        filtered.append((var_name, value, client_id))
        write_env_file(filtered)

    return SetupChange(
        timestamp=now_iso(),
        client_id=client_id,
        method="env_file",
        file=_ENV_FILE,
        detail=export_line,
    )


def add_env_to_shell_profile(
    var_name: str,
    value: str,
    client_id: str,
    profile_path: str = "",
    dry_run: bool = False,
) -> SetupChange | None:
    """Add an env var for a client — write to env file + ensure source block."""
    if not profile_path:
        profile_path = _detect_shell_profile()

    install_source_block(profile_path, dry_run=dry_run)
    return add_env_to_env_file(var_name, value, client_id, dry_run=dry_run)
