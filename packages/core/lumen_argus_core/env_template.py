"""Render the body of ``~/.lumen-argus/env``.

The env file is sourced on every shell startup via a one-line source
block in ``~/.zshrc`` / ``~/.bashrc``.  Two body shapes exist — the
caller picks one explicitly via ``managed_by``:

* ``ManagedBy.CLI`` — unconditional ``export`` lines.  The user ran
  ``lumen-argus-agent protection enable`` from a terminal and owns the
  lifecycle (uninstall = ``protection disable`` or ``setup --undo``).
  No liveness guard because there is no "silent removal" failure mode
  to defend against.

* ``ManagedBy.TRAY`` — exports wrapped in a self-healing liveness
  guard that activates only when the tray-app bundle recorded in
  ``~/.lumen-argus/.app-path`` still exists *or* the enrolled relay
  process is alive.  This is the protection the desktop app and the
  enrollment flow need so a dragged-to-Trash tray app stops intercepting
  traffic without leaving AI tools pointed at a dead proxy.

Hard constraint on the tray body: zero subprocess invocations in the
guard.  Every check is a shell builtin (``[``, ``read``, ``case``,
parameter expansion, ``kill -0``).  ``relay.json`` is parsed with
``while read`` + ``case`` because ``json.dump(indent=2)`` emits one
key per line with a stable ``"key": value`` separator — total cost on
a cold shell is a few ``stat()`` syscalls and one small file read.
"""

from enum import StrEnum


class ManagedBy(StrEnum):
    """Who owns the lifecycle of ``~/.lumen-argus/env``.

    The value is persisted in the status dict returned by
    ``protection_status()`` and surfaced over the ``--managed-by`` CLI
    flag, so it doubles as a stable audit marker.
    """

    CLI = "cli"
    TRAY = "tray"


_HEADER_PREFIX = "# lumen-argus:managed-env ("

_CLI_HEADER = _HEADER_PREFIX + "cli) — do not edit manually\n"

_TRAY_PRELUDE = (
    _HEADER_PREFIX
    + """tray) — do not edit manually
_la_active=0
if [ -f "$HOME/.lumen-argus/enrollment.json" ] && [ -f "$HOME/.lumen-argus/relay.json" ]; then
  _la_pid=
  while IFS= read -r _la_line; do
    case $_la_line in
      *'"pid":'*)
        _la_pid=${_la_line##*: }
        _la_pid=${_la_pid%,}
        break
        ;;
    esac
  done < "$HOME/.lumen-argus/relay.json"
  [ -n "$_la_pid" ] && kill -0 "$_la_pid" 2>/dev/null && _la_active=1
  unset _la_pid _la_line
fi
if [ "$_la_active" = "0" ] && [ -f "$HOME/.lumen-argus/.app-path" ]; then
  read -r _la_app < "$HOME/.lumen-argus/.app-path"
  [ -n "$_la_app" ] && [ -d "$_la_app" ] && _la_active=1
  unset _la_app
fi
if [ "$_la_active" = "1" ]; then
"""
)

_TRAY_EPILOGUE = """fi
unset _la_active
"""


def parse_header_managed_by(first_line: str) -> ManagedBy | None:
    """Extract the ``ManagedBy`` mode from the first line of an env file.

    Returns ``None`` when the line is absent or does not carry a
    recognisable managed-env header — empty file, unrelated third-party
    writer, or a header produced by a newer schema than this reader
    understands.  Callers treat ``None`` as "mode unknown, do not make
    claims about it".
    """
    if not first_line.startswith(_HEADER_PREFIX):
        return None
    tail = first_line[len(_HEADER_PREFIX) :]
    close = tail.find(")")
    if close < 0:
        return None
    try:
        return ManagedBy(tail[:close])
    except ValueError:
        return None


def _format_export(var_name: str, value: str, client_id: str, managed_tag: str, *, indent: str) -> str:
    """Render one ``export`` line with the managed marker appended.

    An empty ``client_id`` preserves an orphan line (no ``client=``
    suffix) so lines written by a non-conformant external writer
    round-trip without gaining a bogus empty suffix.
    """
    if client_id:
        return "%sexport %s=%s  %s client=%s" % (indent, var_name, value, managed_tag, client_id)
    return "%sexport %s=%s  %s" % (indent, var_name, value, managed_tag)


def render_body(
    entries: list[tuple[str, str, str]],
    managed_tag: str,
    *,
    managed_by: ManagedBy,
) -> str:
    """Return the full text of ``~/.lumen-argus/env``.

    An empty ``entries`` list returns an empty string regardless of
    mode — protection is disabled and the file is truncated.

    Args:
        entries: (var_name, value, client_id) tuples.  An empty
            ``client_id`` renders an orphan line.
        managed_tag: the comment marker appended to every export so
            ``read_env_file()`` can identify managed lines.
        managed_by: lifecycle owner.  Controls whether the self-healing
            liveness guard is emitted around the exports.
    """
    if not entries:
        return ""

    match managed_by:
        case ManagedBy.TRAY:
            exports = "\n".join(_format_export(v, val, cid, managed_tag, indent="  ") for v, val, cid in entries)
            return _TRAY_PRELUDE + exports + "\n" + _TRAY_EPILOGUE
        case ManagedBy.CLI:
            exports = "\n".join(_format_export(v, val, cid, managed_tag, indent="") for v, val, cid in entries)
            return _CLI_HEADER + exports + "\n"
        case _:
            # An explicit failure is load-bearing: a hypothetical future
            # ``ManagedBy`` value that silently fell into the CLI branch
            # would strip the liveness guard from machines that depended
            # on it and nobody would notice until the tray app got
            # dragged to Trash.
            raise ValueError("unsupported ManagedBy mode: %r" % managed_by)
