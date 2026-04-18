# Releases

How the build and release system works. For the step-by-step checklist
to cut a release, see [`RELEASE.md`](https://github.com/lumen-argus/lumen-argus/blob/main/RELEASE.md)
at the repo root.

## What a release tag produces

A tag matching `v*` on `main` triggers three independent GitHub Actions
workflows. They all run from the same commit (the tagged one), but
they publish to different places and can succeed or fail independently.

| Workflow | Publishes | Artifacts |
| --- | --- | --- |
| `publish.yml` | `pypi.org` (via TestPyPI first) | Three wheels + sdists: `lumen-argus-core`, `lumen-argus-agent`, `lumen-argus-proxy` |
| `docker.yml` | `ghcr.io/lumen-argus/lumen-argus-community` | Multi-arch image (`linux/amd64` + `linux/arm64`) |
| `binaries.yml` | GitHub Releases (same repo) | Six sidecar binaries (3 platforms × 2 entry points) + `checksums.txt` |

There is no orchestration between them. If `publish.yml` succeeds but
`binaries.yml` fails, the PyPI release stands and the operator reruns
`binaries.yml`. This is deliberate — PyPI uploads are one-way, so
coupling them to a best-effort binary build would make a failed
binary matrix poison an otherwise valid PyPI release.

## Version policy

Each of the three packages carries its own version in
`packages/<name>/pyproject.toml`. They are completely decoupled:
`lumen-argus-core` can be at `0.3.1` while `lumen-argus-proxy` is at
`0.2.5` and `lumen-argus-agent` is at `0.4.0`.

The **git tag** reflects whichever version the release is primarily
identified by in user-facing communication — typically the proxy
version, since that is the consumer-facing binary. The tag is **just a
trigger**; nothing in the build system parses the tag name for a
version number. Each package is built and published at whatever
version is in its `pyproject.toml` at the tagged commit.

When package versions diverge, surface it in the changelog header —
e.g. `## v0.2.0 — 2026-04-18 (core 0.1.1, agent 0.2.0, proxy 0.2.0)`.
Release notes that mention just `v0.2.0` are otherwise ambiguous.

We follow SemVer per-package: patch for bugfixes, minor for new
features, major for breaking changes. Pre-`1.0.0` status is flagged in
the PyPI classifier (`Development Status :: 3 - Alpha`).

## Build targets

### PyPI wheels (`publish.yml`)

Triggered on `v*` tags. Three matrix jobs (one per package) each run:

```bash
uv build --package <package-name>
```

This produces `dist/*.whl` and `dist/*.tar.gz`. Artifacts are uploaded
to GitHub Actions, then:

1. `publish-testpypi` job publishes to TestPyPI using `UV_PUBLISH_TOKEN = secrets.TEST_PYPI_TOKEN`. TestPyPI is the gate — if it fails, PyPI does not run.
2. `publish-pypi` job publishes to PyPI using `UV_PUBLISH_TOKEN = secrets.PYPI_TOKEN`.

There is no signing step — we rely on PyPI's
[trusted publisher](https://docs.pypi.org/trusted-publishers/) model
(OIDC from GitHub Actions to PyPI, scoped to this repo). No GPG or
Sigstore signatures today. See *Signing* below.

### Docker image (`docker.yml`)

Triggered on pushes to `main` and `v*` tags. Builds a multi-arch image
(`linux/amd64`, `linux/arm64`) via Docker Buildx + QEMU, pushes to
`ghcr.io/lumen-argus/lumen-argus-community`.

Tag scheme (via `docker/metadata-action`):

- `latest` — semver tags only (not `main` pushes)
- `X.Y.Z` — full semver
- `X.Y`, `X` — partial semver for major/minor pinning
- `<git-sha>` — always
- branch name — for `main` builds

`main` builds also produce images for canary / nightly use (tagged
with the SHA and branch). Pre-release testing is fine but the `latest`
tag only moves on proper version tags.

### Sidecar binaries (`binaries.yml`)

Triggered on `v*` tags (and `workflow_dispatch` for dry-runs without a
release). Three native-runner matrix builds, each producing two
binaries:

| Runner | Target triple | Binaries |
| --- | --- | --- |
| `macos-14` | `aarch64-apple-darwin` | `lumen-argus-aarch64-apple-darwin`, `lumen-argus-agent-aarch64-apple-darwin` |
| `macos-13` | `x86_64-apple-darwin` | `lumen-argus-x86_64-apple-darwin`, `lumen-argus-agent-x86_64-apple-darwin` |
| `ubuntu-latest` | `x86_64-unknown-linux-gnu` | `lumen-argus-x86_64-unknown-linux-gnu`, `lumen-argus-agent-x86_64-unknown-linux-gnu` |

Naming follows the Rust target-triple convention so downstream repos
that already use it (e.g. Tauri sidecar packaging) can drop the files
into place without remapping.

**Linux `aarch64` is not shipped as a PyInstaller binary.** That audience is covered by the multi-arch Docker image (`docker.yml` publishes `linux/arm64` alongside `linux/amd64`) or by building from source with the same spec CI uses. Adding the platform back is a one-line matrix change if a concrete consumer shows up.

Each build runs `uv sync` (which pulls PyInstaller from the workspace
dev-dependencies) then:

```bash
uv run pyinstaller packages/proxy/lumen-argus.spec   --distpath dist --workpath build
uv run pyinstaller packages/agent/lumen-argus-agent.spec --distpath dist --workpath build
```

The specs invoke `scripts/generate_build_info.py` **before** `Analysis()`
collects the package, which writes `<package>/_build_info.py` with:

- `VERSION` — from the package's `pyproject.toml`
- `GIT_COMMIT` — from `git rev-parse HEAD` (requires the checkout to have history — `binaries.yml` uses `fetch-depth: 0`)
- `BUILT_AT` — UTC `isoformat()` at build time

The `_build_info.py` file is gitignored and only exists inside built
binaries. Dev runs from source fall back to `"unknown"` for these
fields, while `build_id` (see below) remains authoritative because it
hashes `sys.executable` at runtime.

After build, each binary is:

1. Renamed to `<binary>-<target-triple>` (e.g. `lumen-argus` → `lumen-argus-aarch64-apple-darwin`).
2. **Smoke-tested**: the workflow spawns the proxy, waits for its dashboard port, hits `GET /api/v1/build`, and asserts that the `build_id` it reports is exactly `sha256:<hash-of-binary-on-disk>`. This catches the nightmare scenario where `compute_build_id` gets reworked and silently decouples the endpoint from the binary bytes. A mismatch fails the build — the release does not publish.
3. Hashed with `shasum -a 256` into a per-binary `.sha256` file.

The `release` job then downloads all three platforms' artifacts,
aggregates `.sha256` files into a single `checksums.txt` (sorted by
filename), generates release notes with versions + per-binary hashes,
and creates the GitHub Release.

## Build identity and the cross-repo contract

This is the contract that downstream repos bundling the sidecar binary
rely on.

### What `build_id` means

`build_id` is defined in `lumen_argus_core.build_info.compute_build_id()`
as:

```python
"sha256:" + hashlib.sha256(open(sys.executable, "rb").read()).hexdigest()
```

It is computed **once per process**, cached via `functools.cache`, and
exposed at `GET /api/v1/build` on both the proxy dashboard (`:8081`,
behind auth) and the agent relay (`:8070`, loopback-only, no auth —
mirrors `/health`).

Two processes with the same `build_id` are running **identical binary
bytes**. This is the primitive a supervisor uses to answer "is this
running process the one I expect?" — far more reliable than a version
string or a PID, because it catches the case where the binary on disk
was replaced between spawn and the next request.

The auto-update failure mode this is designed to surface: if the
on-disk binary is replaced between spawn and the next request (new
release installed, downstream auto-updater swapped the file), lazy
imports inside the running process can fail (`zlib.error: Error -3`
has been seen) and `/api/v1/status` may still return 200 even while
the dashboard returns 500. Comparing `build_id` against a
known-expected hash is the reliable way to catch this before trusting
the process.

### What a release publishes

For each binary in each release:

- The binary itself, as a GitHub Release asset.
- Its SHA-256 hash, in two forms:
  - `checksums.txt` attached to the release (one line per binary: `<hex>  <filename>`, sorted).
  - Per-binary markdown bullet in the release body: `` - `<filename>` — `sha256:<hex>` ``.

### How downstream repos consume it

A downstream repo bundling the sidecar does this at their build time:

1. Fetch the binary for each platform it ships (typically via their own CI downloading release assets).
2. Record the hash in whatever manifest format they use. For a repo that ships a JSON manifest alongside the binary, that looks like:
   ```json
   {
     "lumen-argus-aarch64-apple-darwin": {
       "build_id": "sha256:abc123…"
     }
   }
   ```
3. At runtime, when the supervisor considers reusing an already-running sidecar, it hits `GET /api/v1/build` on the sidecar and compares the reported `build_id` against the manifest entry for the binary it shipped. Match → reuse. Mismatch → the binary on disk was replaced since spawn, kill and respawn.

The hash in `checksums.txt` and the `build_id` reported by the running
process are **the same value** (modulo the `sha256:` prefix). There is
no translation step.

### Reproducibility

The binary hash depends on the build environment: Python version,
PyInstaller version, platform, and the commit's source tree. The
workflow pins:

- **Python 3.12** (`actions/setup-python@v5` with `python-version: "3.12"`).
- **PyInstaller `>=6.19.0`** (from root `pyproject.toml` dev-dependencies; resolved via `uv sync`).
- **Native runners** (no cross-compilation; each binary is built on a runner that matches its target triple).

Rebuilding from the same tag on the same runner image generally
produces the same hash, but PyInstaller is not bit-deterministic in
all cases (timestamp metadata, Python bytecode compilation order,
etc.). Downstream repos should take the hash published in the release
as authoritative rather than rebuild-and-compare.

## Signing (currently deferred)

Nothing is signed today:

- **PyPI wheels**: uploaded via PyPI trusted publisher (OIDC), not GPG- or Sigstore-signed.
- **Docker images**: pushed to GHCR with registry auth only; not cosigned.
- **Sidecar binaries**: the PyInstaller specs read `CODESIGN_IDENTITY` and `ENTITLEMENTS_FILE` environment variables (`packages/proxy/lumen-argus.spec` lines 95–96, and equivalent in the agent spec), but the CI workflow does not populate them. macOS users will see Gatekeeper quarantine warnings on downloaded binaries; downstream repos that re-distribute the binaries typically re-sign under their own identity.

Adding signing is tracked as a future improvement. The skeleton in the
specs is intentional — when we land codesigning, the workflow will
inject the identity + entitlements file and the specs already know
how to consume them.

## Release philosophy

- **No release branches.** Tags are cut from `main`. This is documented project policy, not a workflow limitation.
- **Independent package versions.** Don't force-sync three `pyproject.toml` files just because you cut a single tag.
- **Best-effort workflows.** A broken binary build does not roll back a successful PyPI publish. Cut the next patch if needed; do not try to reverse the first release.
- **Publish hashes, not trust.** Downstream repos should not need to rebuild from source to verify identity. The authoritative `build_id` hash is in `checksums.txt`.

## Related

- [`RELEASE.md`](https://github.com/lumen-argus/lumen-argus/blob/main/RELEASE.md) — the runbook.
- [`docs/development/changelog.md`](changelog.md) — human-readable release history.
- [`docs/reference/api-endpoints.md`](../reference/api-endpoints.md) — documents `GET /api/v1/build` on both services.
- [`.github/workflows/publish.yml`](https://github.com/lumen-argus/lumen-argus/blob/main/.github/workflows/publish.yml), [`docker.yml`](https://github.com/lumen-argus/lumen-argus/blob/main/.github/workflows/docker.yml), [`binaries.yml`](https://github.com/lumen-argus/lumen-argus/blob/main/.github/workflows/binaries.yml) — the workflows themselves.
