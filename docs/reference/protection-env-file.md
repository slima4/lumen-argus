# Protection Env File

`protection enable` writes tool base-URL environment variables to
`~/.lumen-argus/env`.  That file is sourced by your shell on every
startup through a one-line source block in `~/.zshrc` / `~/.bashrc`.

The file has **two body shapes**, picked by the caller via
`--managed-by` (or `enable_protection(..., managed_by=...)` in
Python):

| Mode | Caller | Body | Failure mode it defends |
|------|--------|------|-------------------------|
| `cli` *(default)* | User running the binary from a terminal (source install, `pip`, `brew`) | **Unconditional exports.** The user owns the lifecycle — uninstall means running `protection disable` or `setup --undo`. | None. No silent-removal failure mode exists in this workflow. |
| `tray` | Desktop tray app sidecar + enrollment flow | **Self-healing liveness guard.** Exports activate only when the tray-app bundle recorded in `~/.lumen-argus/.app-path` still exists *or* the enrolled relay PID is alive. | A dragged-to-Trash tray app silently pointing AI tools at a dead `127.0.0.1` proxy. |

lumen-argus does **not** infer the mode from the environment (no
parent-process sniffing, no Docker/brew/pip detection).  The invoker
states the mode explicitly.  The chosen mode is recorded in the file
header and echoed back in the status dict (`managed_by` field) so
callers can verify the file they are looking at is the one they wrote.

### Mode is sticky

Once a mode is recorded in the file header, downstream mutators that
do not know the mode (`setup`, `add_env_to_env_file`, etc.) preserve
it.  Running `lumen-argus setup` on an enrolled machine will not strip
the liveness guard — a write with no explicit `--managed-by` reads the
existing header and keeps the same shape.  Changing the mode requires
an explicit `protection enable --managed-by …`.

### Status contract

`lumen-argus protection status` returns a JSON document with the
following keys:

| Key | Type | Meaning |
|-----|------|---------|
| `enabled` | bool | `true` iff the env file has at least one managed export line |
| `env_file` | string | absolute path to `~/.lumen-argus/env` |
| `env_vars_set` | int | number of managed exports in the file |
| `managed_by` | `"cli"` / `"tray"` / `null` | mode recorded in the file header; `null` when disabled or the file lacks a recognised header |

The same keys plus `managed_by` also come back from `protection
enable`.  A tray-app or dashboard consumer that persists "I last wrote
this file as X" compares X against `managed_by` here to detect drift.

## File location and permissions

| Path | Mode | Owner | Purpose |
|------|------|-------|---------|
| `~/.lumen-argus/env` | `0o600` | the user | sourced by the shell |
| `~/.lumen-argus/.env.lock` | `0o600` | the user | `fcntl` lock held during writes |
| `~/.lumen-argus/.app-path` | `0o600` | the user | tray app bundle path marker (written by the desktop app on every launch) |
| `~/.lumen-argus/enrollment.json` | `0o600` | the user | enrollment proof (dedicated mode only) |
| `~/.lumen-argus/relay.json` | `0o600` | the user | live relay state (dedicated mode only) |

`0o600` on the env file is load-bearing: the shell sources it as
trusted code, so group- or world-writable permissions would be an
arbitrary-code-execution vector.

## Source block

A single block in your shell profile sources the env file when it
exists.  It is idempotent and written exactly once:

```bash
# lumen-argus:begin
[ -f "$HOME/.lumen-argus/env" ] && source "$HOME/.lumen-argus/env"
# lumen-argus:end
```

## CLI mode body (`--managed-by cli`, default)

Straight `export` lines.  The header tags the mode so a reader of the
file can see which lifecycle it belongs to.

```bash
# lumen-argus:managed-env (cli) — do not edit manually
export ANTHROPIC_BASE_URL=http://127.0.0.1:8070  # lumen-argus:managed client=claude_code
export OPENAI_BASE_URL=http://127.0.0.1:8070  # lumen-argus:managed client=aider
```

No guard — the exports take effect unconditionally.  This is the
correct default for a user who cloned the repo, ran `uv sync`, and
started the proxy themselves: they started it, they can stop it, and
they do not need the guard.

## Tray mode body (`--managed-by tray`)

`protection enable --managed-by tray` (used by the desktop tray app
sidecar and by the enrollment flow) wraps the exports in a pure-shell
liveness guard:

```bash
# lumen-argus:managed-env — do not edit manually
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
  export ANTHROPIC_BASE_URL=http://127.0.0.1:8070  # lumen-argus:managed client=claude_code
  export OPENAI_BASE_URL=http://127.0.0.1:8070  # lumen-argus:managed client=aider
fi
unset _la_active
```

The header tag `(tray)` is the audit marker — a reader can tell at a
glance which lifecycle this file belongs to.

`protection disable` truncates the file to empty bytes regardless of
mode; the source block in your shell profile is a no-op on an empty
file.

## Guard semantics (tray mode only)

Two independent checks, in order:

1.  **Dedicated mode** — if `enrollment.json` and `relay.json` both
    exist, parse the relay PID from `relay.json` and probe it with
    `kill -0`.  A live PID means the relay service is intercepting
    traffic on behalf of the user's organization, so the exports stay
    on even when the tray app itself has been removed.

2.  **Local mode** — if the dedicated check did not activate, read
    `.app-path` and check that the recorded bundle directory still
    exists.  `.app-path` is rewritten by the tray app on every launch,
    so dragging the app to Trash makes the path dangle immediately and
    the guard stops exporting.

If neither check activates, the exports are skipped entirely and the
shell keeps whatever `ANTHROPIC_BASE_URL` etc. the user already had.

## Activation matrix (tray mode)

| Tray app bundle | Enrollment | Relay PID | Exports? | Effective route |
|-----------------|-----------|-----------|----------|-----------------|
| present         | —         | —         | yes      | via proxy / relay |
| missing         | missing   | —         | no       | direct to provider |
| missing         | present   | alive     | yes      | via relay |
| missing         | present   | dead      | no       | direct to provider |
| missing         | present   | `relay.json` missing | no | direct to provider |

CLI mode does not have an activation matrix — exports are always on
while the file exists.

## Zero-subprocess parser

The guard uses only shell builtins — no `python3`, no `jq`, no `grep`
subprocess.  PID extraction leans on the stable shape of
`json.dump(…, indent=2)` output: one key per line, `"key": value`
separator.  The parser walks the file with `while read`, matches
`*'"pid":'*` in a `case`, and strips the value with two parameter
expansions:

```bash
_la_pid=${_la_line##*: }   # drop everything up to and including "key": "
_la_pid=${_la_pid%,}       # drop trailing comma (none if pid is last key)
```

Total cost on a cold shell: two or three `stat()` syscalls plus one
small file read — well under 1 ms in every mode.  The previous
`curl`-probe and `python3`-parse variants were discarded because they
added tens to hundreds of milliseconds to every interactive shell
startup.

## Managed-line format

Each active export is tagged for clean identification and undo:

```
export <VAR>=<value>  # lumen-argus:managed client=<client_id>
```

(In tray mode the line is two-space indented inside the `if ...; then`
block; `read_env_file()` tolerates both shapes.)

The double-space before the tag is load-bearing — `read_env_file()`
uses it as the delimiter that separates the value from the managed
marker.  Lines without a `client=` suffix are recognised as
**orphans**: preserved on read/write round-trip, evicted when a
canonical entry for the same variable is written.

## Choosing a mode

| You are… | Use |
|----------|-----|
| A user running the proxy from a terminal (source, `pip`, `brew`) | `--managed-by cli` (the default — no flag needed) |
| The desktop tray app writing the env file through its agent sidecar | `--managed-by tray` |
| The enrollment flow (`lumen-argus-agent enroll`) | `--managed-by tray` — handled automatically |
| A Docker deployment | Neither — `~/.lumen-argus/env` is not used inside containers. Set `ANTHROPIC_BASE_URL` directly in your compose / host shell. |

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Tools reach provider directly in tray mode even with tray app running | `.app-path` missing or stale | Launch the tray app once — it rewrites `.app-path` |
| Tools reach provider directly after enrollment | `relay.json` missing or PID dead | `lumen-argus-agent relay` (or restart the relay launchd service) |
| `echo $ANTHROPIC_BASE_URL` empty in a new terminal right after install | New terminals inherit env at login; the source block runs at shell startup | Open a new terminal *after* the source block was added, or source `~/.lumen-argus/env` manually |
| `echo $ANTHROPIC_BASE_URL` empty but the CLI proxy is running | Env file was written with `--managed-by tray` but nothing wrote `.app-path` / `relay.json` | Re-run `lumen-argus protection enable` (default `--managed-by cli` — unconditional exports) |
| Env file exists but is empty | `protection disable` truncated it | `lumen-argus protection enable` |

## Related

-   Layer 3 of the [clean-uninstall spec](https://github.com/lumen-argus/lumen-argus) covers the five-layer design that this env file participates in.
-   [Client detection and setup](../guide/client-detection.md) explains how the env file is populated from the client registry.
-   [CLI reference](cli.md) documents `lumen-argus protection {enable,disable,status}`.
