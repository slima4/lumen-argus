# Releasing lumen-argus

This is the action-oriented runbook. For how the build system actually
works, see [`docs/development/releases.md`](docs/development/releases.md).

A release tag (`vX.Y.Z`) publishes **three** things from a single commit:

1. **PyPI packages** — `lumen-argus-core`, `lumen-argus-agent`, `lumen-argus-proxy` (`.github/workflows/publish.yml`)
2. **Docker image** — `ghcr.io/lumen-argus/lumen-argus-community` (`.github/workflows/docker.yml`)
3. **Sidecar binaries + `checksums.txt`** — uploaded to the GitHub Release (`.github/workflows/binaries.yml`)

Each workflow is triggered independently by the tag. If one fails, the
others may still succeed — see *Common failures* below.

---

## Pre-flight

Run this checklist on `main` before cutting anything. Do not start
bumping versions until it is green.

- [ ] `main` CI is green — latest commit shows all jobs passing on `.github/workflows/test.yml`, `docs.yml`, `docker.yml` (where applicable).
- [ ] Local tests pass on your machine:
      ```bash
      uv sync
      uv run python -m unittest discover packages/core/tests/
      uv run python -m unittest discover packages/agent/tests/
      uv run python -m unittest discover tests/
      ```
- [ ] `docs/development/changelog.md` has an `## Unreleased` section and it reflects what you are about to ship. If entries are missing, add them before tagging — the workflow does not scrape commit messages.
- [ ] Version numbers for all three packages are decided. They are independent (see *Version policy* in the reference doc). Common case: bump everything that changed and leave unchanged packages alone.
- [ ] The tag you intend to push does not already exist on the remote:
      ```bash
      git ls-remote --tags origin | grep -F "refs/tags/vX.Y.Z" && echo "TAG EXISTS — pick another"
      ```
- [ ] A dry-run of `binaries.yml` has run cleanly on the current commit at least once (via `workflow_dispatch` from the Actions tab). This catches PyInstaller breakage on all three platforms *before* the tag, where recovery is cheap.

Optional but recommended:

- [ ] Fresh `venv` smoke-install off a local build to sanity-check imports:
      ```bash
      uv build --package lumen-argus-proxy
      python3 -m venv /tmp/smoke && /tmp/smoke/bin/pip install dist/lumen_argus_proxy-*.whl
      /tmp/smoke/bin/lumen-argus --help
      ```

---

## Cutting the release

All steps run on `main`. We do not use release branches — tag and
push.

### 1. Bump package versions

Each package owns its own version. Edit the three `pyproject.toml`
files:

```
packages/core/pyproject.toml   →  version = "X.Y.Z"
packages/agent/pyproject.toml  →  version = "X.Y.Z"
packages/proxy/pyproject.toml  →  version = "X.Y.Z"
```

No bump tool exists — do this by hand. If a package has no changes
since the last release, you may leave its version alone; `uv publish`
will refuse to republish an existing version with a clear error.

### 2. Update the changelog

Open `docs/development/changelog.md`. Rename the `## Unreleased`
header to `## vX.Y.Z — YYYY-MM-DD` and start a fresh empty
`## Unreleased` section above it.

If individual package versions diverge from the tag number, note it
inline — e.g. `## v0.2.0 — 2026-04-18 (core 0.1.1, agent 0.2.0, proxy 0.2.0)`.

### 3. Commit

```bash
git add packages/core/pyproject.toml packages/agent/pyproject.toml packages/proxy/pyproject.toml docs/development/changelog.md
git commit -m "chore(release): vX.Y.Z"
```

### 4. Tag and push

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin main
git push origin vX.Y.Z
```

Pushing the tag is what triggers the three release workflows. You can
watch them under the **Actions** tab — `publish` (PyPI), `Docker`, and
`binaries` (GitHub Release).

---

## Verification

After the tag is pushed, step through these in order. Budget 15–25
minutes for `binaries.yml` (three platforms, PyInstaller is slow).

### PyPI

- [ ] `publish.yml` → `publish-testpypi` job is green. TestPyPI is the gate; PyPI only runs if it succeeds.
- [ ] `publish.yml` → `publish-pypi` job is green.
- [ ] Packages are visible:
      - https://pypi.org/project/lumen-argus-core/
      - https://pypi.org/project/lumen-argus-agent/
      - https://pypi.org/project/lumen-argus-proxy/
- [ ] Install from PyPI in a throwaway venv and confirm the reported version:
      ```bash
      python3 -m venv /tmp/verify && /tmp/verify/bin/pip install lumen-argus-proxy==X.Y.Z
      /tmp/verify/bin/lumen-argus --version
      ```

### Docker

- [ ] `Docker` workflow is green.
- [ ] Image pulls and runs:
      ```bash
      docker pull ghcr.io/lumen-argus/lumen-argus-community:X.Y.Z
      docker run --rm -p 8080:8080 -p 8081:8081 ghcr.io/lumen-argus/lumen-argus-community:X.Y.Z &
      curl -s http://127.0.0.1:8081/api/v1/build | python3 -m json.tool
      ```
- [ ] `version` in the response matches the released proxy version.

### Sidecar binaries

- [ ] `binaries.yml` → three `build` matrix jobs all green (`aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`). The smoke-test step inside each build spawns the binary and confirms `GET /api/v1/build.build_id` matches `sha256(binary)` — if that step fails on any platform, the release is blocked. Linux `aarch64` is not shipped as a PyInstaller binary; see note below.
- [ ] `binaries.yml` → `release` job is green.
- [ ] GitHub Release page exists at `https://github.com/lumen-argus/lumen-argus/releases/tag/vX.Y.Z` with:
      - All 3 `lumen-argus-<triple>` binaries
      - All 3 `lumen-argus-agent-<triple>` binaries
      - `checksums.txt` (6 lines, one per binary, sorted by filename)
- [ ] Download a binary on your platform and confirm its hash against `checksums.txt`:
      ```bash
      shasum -a 256 -c checksums.txt
      ```

---

## Publishing the sidecar `build_id` for downstream repos

This is the cross-repo contract. Downstream repos that bundle a sidecar
binary and verify it at runtime need the binary's `build_id` hash
ahead of time.

**We publish it two ways** — pick whichever your consumer prefers:

1. **`checksums.txt` attached to the release** (machine-readable).
   Each line is `<sha256_hex>  <filename>`. The `build_id` the running
   process reports at `GET /api/v1/build` is `sha256:<sha256_hex>` for
   the filename that matches the binary they are running.

2. **Release body, human-readable** — the auto-generated release notes
   include a `## Sidecar binaries` section with each binary's
   `build_id` as a markdown bullet.

Downstream consumers update their own manifest (e.g. a JSON file
bundled into their build) from one of these sources. Nothing else from
lumen-argus needs to change to support them.

If a downstream repo is blocked because it needs the hash in a
different shape (e.g. a JSON file alongside `checksums.txt`), open an
issue — the auto-generated release notes are cheap to extend.

---

## Rollback

**PyPI and Docker `latest` cannot be unpublished safely.** Release
actions are one-way. If you need to fix a mistake, cut a new patch.

| Mistake | Recovery |
| --- | --- |
| Wrong version number committed and tagged | Delete the tag locally and remotely (`git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z`), re-tag with the right number. **Only safe if no workflow has published yet.** PyPI considers the upload final once it succeeds. |
| PyPI upload succeeded with broken code | Cut `vX.Y.(Z+1)` with the fix. PyPI will not let you overwrite. |
| GitHub Release is wrong (e.g. binaries failed smoke test) | Delete the release (keeps the tag) via `gh release delete vX.Y.Z`, fix the cause, rerun `binaries.yml` via `workflow_dispatch` **pointed at the tag ref**, or cut a new patch if the fix requires a code change. |
| Docker image tag is wrong | `docker.yml` retags `latest` on every tag push. Overwriting with a new patch effectively supersedes the bad one, but the old digest lingers in registry history. |
| Changelog has a typo | Edit `docs/development/changelog.md` on `main` in a follow-up commit. The GitHub Release body is a frozen snapshot — you can also edit it manually via the GitHub UI. |

When in doubt: **cut the next patch**. Explicitly yanking a PyPI
version (`pip install` still resolves it but marks it skipped for new
installs) is only worth it when the bad version is actively harmful,
not just wrong.

---

## Common failures

### `publish-testpypi` fails with "File already exists"

TestPyPI never deletes uploads. A previous dry-run of the same version
is stuck there. Bump to the next patch — TestPyPI is not worth a manual
cleanup.

### `publish-pypi` fails with "File already exists"

You pushed a tag with an unchanged package version. PyPI will not let
you re-upload. Bump the package's version and cut a new tag.

### `binaries.yml` smoke test fails: "build_id mismatch"

The running binary reports a different `build_id` than
`sha256(binary_on_disk)`. This means either:

- `compute_build_id()` has been changed to hash something other than `sys.executable` (regression — revert),
- PyInstaller is producing a non-deterministic wrapper that rewrites itself at runtime (unexpected — investigate on the failing platform),
- the binary's file mode was changed between hash and spawn (e.g. a chmod in the workflow) — unlikely but check the step diff.

### "We need a Linux aarch64 PyInstaller binary"

Not shipped. Two supported paths:

- **Docker**: `ghcr.io/lumen-argus/lumen-argus-community` is multi-arch and already publishes `linux/arm64`. Fronts the same proxy.
- **Build from source** on an aarch64 Linux host: `uv sync && uv run pyinstaller packages/proxy/lumen-argus.spec --distpath dist --workpath build`. Same spec CI uses; the result is a `lumen-argus` binary in `dist/`.

If there is a real consumer that cannot use either, reopen the matrix entry in `binaries.yml` (an `ubuntu-24.04-arm` runner row covers it) rather than working around it downstream.

### `UV_PUBLISH_TOKEN` is invalid / expired

Rotate the token in PyPI / TestPyPI account settings, update the
`TEST_PYPI_TOKEN` / `PYPI_TOKEN` secrets on the repo (Settings →
Secrets and variables → Actions), rerun the failed jobs. The tag does
not need to move.

### Tag already exists

```bash
git tag -d vX.Y.Z                      # local
git push origin :refs/tags/vX.Y.Z      # remote (only if no workflow has published)
```

If PyPI has already accepted an upload under this version, do **not**
delete the tag — cut `vX.Y.(Z+1)` instead. The old tag becomes a
historical record of the broken release.

### `generate_build_info.py` writes `git_commit: "unknown"` in a build

The workflow uses `fetch-depth: 0` so this should not happen in CI. If
it does, the checkout action is not fetching tags — check the
workflow's `actions/checkout` step. In **local** builds (outside CI) the
script falls back to `unknown` when `git rev-parse HEAD` fails, which
is expected and documented.

---

## Operator-specific notes

Paths, credentials references, and per-machine provisioning state do
not belong in this public runbook. If you are the release operator,
keep them in a sibling file named `RELEASE.local.md` — the repo's
`.gitignore` excludes it.
