#!/usr/bin/env python3
"""Generate ``<package>/_build_info.py`` for PyInstaller builds.

Invoked from ``packages/proxy/lumen-argus.spec`` and
``packages/agent/lumen-argus-agent.spec`` at spec eval time, so
``_build_info.py`` exists on disk before ``Analysis()`` collects it.

Contract: writes module-level string constants ``VERSION``,
``GIT_COMMIT``, ``BUILT_AT`` which ``lumen_argus_core.build_info``
reads at request time. The file is gitignored — only the built binary
carries it. In dev runs the module is absent and the helper falls back
to an explicit version string.

Usage:
    python scripts/generate_build_info.py \\
        --package-dir packages/proxy/lumen_argus \\
        --pyproject  packages/proxy/pyproject.toml
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import subprocess
import sys
import tomllib


def _read_version(pyproject_path: str) -> str:
    with open(pyproject_path, "rb") as f:
        data = tomllib.load(f)
    try:
        return str(data["project"]["version"])
    except KeyError as exc:
        raise SystemExit("generate_build_info: %s missing [project].version" % pyproject_path) from exc


def _read_git_commit(cwd: str) -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=cwd,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return "unknown"
    return out.decode("ascii", errors="replace").strip() or "unknown"


def _now_utc_rfc3339() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_TEMPLATE = '''"""Auto-generated at PyInstaller build time. Do not edit or commit."""

VERSION = {version!r}
GIT_COMMIT = {git_commit!r}
BUILT_AT = {built_at!r}
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--package-dir",
        required=True,
        help="Target package directory (e.g. packages/proxy/lumen_argus)",
    )
    parser.add_argument(
        "--pyproject",
        required=True,
        help="Path to the package's pyproject.toml",
    )
    parser.add_argument(
        "--git-root",
        default=None,
        help="Git repo root for rev-parse (defaults to pyproject's dir)",
    )
    args = parser.parse_args()

    package_dir = os.path.abspath(args.package_dir)
    pyproject = os.path.abspath(args.pyproject)
    git_root = os.path.abspath(args.git_root) if args.git_root else os.path.dirname(pyproject)

    if not os.path.isdir(package_dir):
        print("generate_build_info: package dir does not exist: %s" % package_dir, file=sys.stderr)
        return 2
    if not os.path.isfile(pyproject):
        print("generate_build_info: pyproject not found: %s" % pyproject, file=sys.stderr)
        return 2

    version = _read_version(pyproject)
    git_commit = _read_git_commit(git_root)
    built_at = _now_utc_rfc3339()

    target = os.path.join(package_dir, "_build_info.py")
    content = _TEMPLATE.format(version=version, git_commit=git_commit, built_at=built_at)
    with open(target, "w", encoding="utf-8") as f:
        f.write(content)

    print(
        "generate_build_info: wrote %s (version=%s git_commit=%s built_at=%s)"
        % (target, version, git_commit[:12], built_at)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
