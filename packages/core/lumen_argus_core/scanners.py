"""Install-method scanners — detect AI tools on disk.

Each scanner checks one installation method (binary, pip, npm, brew,
VS Code extension, JetBrains plugin, app bundle, neovim plugin) and
returns a DetectedClient if found.

Called by detect.py orchestration. Read-only — never modifies files.
"""

from __future__ import annotations

import glob
import json
import logging
import os
import platform
import shutil
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lumen_argus_core.clients import ClientDef

from lumen_argus_core.detect_models import VERSION_RE, DetectedClient, InstallMethod, get_vscode_variants

log = logging.getLogger("argus.detect")


def scan_binary(client: ClientDef) -> DetectedClient | None:
    """Check if a CLI binary exists in PATH."""
    for name in client.detect_binary:
        path = shutil.which(name)
        if path:
            log.debug("binary found: %s → %s", name, path)
            return DetectedClient(
                client_id=client.id,
                display_name=client.display_name,
                installed=True,
                install_method=InstallMethod.BINARY,
                install_path=path,
                proxy_config_type=client.proxy_config.config_type.value,
                setup_instructions=client.proxy_config.setup_instructions,
                website=client.website,
            )
    return None


def scan_pip_package(client: ClientDef) -> DetectedClient | None:
    """Check if a pip package is installed (no subprocess — uses importlib.metadata)."""
    if not client.detect_pip:
        return None
    try:
        from importlib.metadata import version as pkg_version

        ver = pkg_version(client.detect_pip)
        log.debug("pip package found: %s==%s", client.detect_pip, ver)
        return DetectedClient(
            client_id=client.id,
            display_name=client.display_name,
            installed=True,
            version=ver,
            install_method=InstallMethod.PIP,
            install_path="pip:%s" % client.detect_pip,
            proxy_config_type=client.proxy_config.config_type.value,
            setup_instructions=client.proxy_config.setup_instructions,
            website=client.website,
        )
    except ImportError:
        log.debug("importlib.metadata not available")
        return None
    except Exception as e:
        err_name = type(e).__name__
        if "NotFound" in err_name or "PackageNotFound" in err_name:
            log.debug("pip package %s not installed", client.detect_pip)
        else:
            log.warning("unexpected error checking pip package %s: %s", client.detect_pip, e, exc_info=True)
        return None


def scan_vscode_extension(client: ClientDef) -> DetectedClient | None:
    """Check if a VS Code extension is installed across all VS Code variants."""
    if not client.detect_vscode_ext:
        return None
    ext_id_lower = client.detect_vscode_ext.lower()

    for variant in get_vscode_variants():
        for ext_dir in variant.extensions:
            ext_dir = os.path.expanduser(ext_dir)
            if not os.path.isdir(ext_dir):
                continue
            pattern = os.path.join(ext_dir, "%s-*" % ext_id_lower)
            matches = glob.glob(pattern)
            if matches:
                match_path = sorted(matches)[-1]
                dir_name = os.path.basename(match_path)
                version = ""
                dash_idx = dir_name.rfind("-")
                if dash_idx > 0:
                    version = dir_name[dash_idx + 1 :]
                log.debug("VS Code extension found: %s in %s (%s)", client.detect_vscode_ext, variant.name, dir_name)
                return DetectedClient(
                    client_id=client.id,
                    display_name=client.display_name,
                    installed=True,
                    version=version,
                    install_method=InstallMethod.VSCODE_EXT,
                    install_path=match_path,
                    proxy_config_type=client.proxy_config.config_type.value,
                    setup_instructions=client.proxy_config.setup_instructions,
                    website=client.website,
                )
    return None


def scan_app_bundle(client: ClientDef) -> DetectedClient | None:
    """Check for macOS .app bundle in /Applications."""
    if not client.detect_app_name or platform.system() != "Darwin":
        return None
    app_path = "/Applications/%s" % client.detect_app_name
    if os.path.isdir(app_path):
        version = ""
        plist_path = os.path.join(app_path, "Contents", "Info.plist")
        if os.path.exists(plist_path):
            try:
                import plistlib

                with open(plist_path, "rb") as f:
                    info = plistlib.load(f)
                version = info.get("CFBundleShortVersionString", "")
                log.debug("app bundle version: %s → %s", client.detect_app_name, version)
            except Exception as e:
                log.warning("failed to read Info.plist for %s: %s", client.detect_app_name, e)
        log.debug("app bundle found: %s", app_path)
        return DetectedClient(
            client_id=client.id,
            display_name=client.display_name,
            installed=True,
            version=version,
            install_method=InstallMethod.APP_BUNDLE,
            install_path=app_path,
            proxy_config_type=client.proxy_config.config_type.value,
            setup_instructions=client.proxy_config.setup_instructions,
            website=client.website,
        )
    return None


def scan_jetbrains_plugin(client: ClientDef) -> DetectedClient | None:
    """Check for JetBrains IDE plugins."""
    if not client.detect_jetbrains_plugin:
        return None

    system = platform.system()
    if system == "Darwin":
        base = os.path.expanduser("~/Library/Application Support/JetBrains")
    elif system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        base = os.path.join(appdata, "JetBrains") if appdata else ""
    else:
        base = os.path.expanduser("~/.local/share/JetBrains")

    if not os.path.isdir(base):
        return None

    try:
        entries = os.listdir(base)
    except OSError as e:
        log.debug("could not list JetBrains dir %s: %s", base, e)
        return None
    for product_dir in entries:
        plugin_dir = os.path.join(base, product_dir, "plugins", client.detect_jetbrains_plugin)
        if os.path.isdir(plugin_dir):
            log.debug("JetBrains plugin found: %s in %s", client.detect_jetbrains_plugin, product_dir)
            return DetectedClient(
                client_id=client.id,
                display_name=client.display_name,
                installed=True,
                install_method=InstallMethod.JETBRAINS_PLUGIN,
                install_path=plugin_dir,
                proxy_config_type=client.proxy_config.config_type.value,
                setup_instructions=client.proxy_config.setup_instructions,
                website=client.website,
            )
    return None


def scan_npm_package(client: ClientDef) -> DetectedClient | None:
    """Check if an npm global package is installed by reading package.json."""
    if not client.detect_npm:
        return None

    npm_prefixes = _get_npm_prefixes()

    for prefix in npm_prefixes:
        pkg_dir = os.path.join(prefix, client.detect_npm)
        pkg_json = os.path.join(pkg_dir, "package.json")
        if not os.path.isfile(pkg_json):
            continue
        version = ""
        try:
            with open(pkg_json, "r", encoding="utf-8") as f:
                data = json.load(f)
            version = data.get("version", "")
            log.debug("npm package found: %s@%s at %s", client.detect_npm, version, prefix)
        except (json.JSONDecodeError, OSError) as e:
            log.warning("could not read package.json for %s: %s", client.detect_npm, e)
        return DetectedClient(
            client_id=client.id,
            display_name=client.display_name,
            installed=True,
            version=version,
            install_method=InstallMethod.NPM,
            install_path=pkg_dir,
            proxy_config_type=client.proxy_config.config_type.value,
            setup_instructions=client.proxy_config.setup_instructions,
            website=client.website,
        )
    return None


def _get_npm_prefixes() -> list[str]:
    """Build list of global node_modules directories to search."""
    prefixes: list[str] = []
    npm_root = os.environ.get("NPM_CONFIG_PREFIX", "")
    if npm_root:
        prefixes.append(os.path.join(npm_root, "lib", "node_modules"))
    # nvm-managed
    nvm_dir = os.environ.get("NVM_DIR", os.path.expanduser("~/.nvm"))
    if os.path.isdir(nvm_dir):
        current = os.path.join(nvm_dir, "current", "lib", "node_modules")
        if os.path.isdir(current):
            prefixes.append(current)
    # fnm-managed
    fnm_dir = os.environ.get("FNM_DIR", "")
    if not fnm_dir:
        if platform.system() == "Darwin":
            fnm_dir = os.path.expanduser("~/Library/Application Support/fnm")
        else:
            fnm_dir = os.path.expanduser("~/.local/share/fnm")
    if os.path.isdir(fnm_dir):
        fnm_current = os.path.join(fnm_dir, "node-versions")
        if os.path.isdir(fnm_current):
            fnm_default = os.path.join(fnm_dir, "aliases", "default")
            if os.path.isdir(fnm_default):
                modules = os.path.join(fnm_default, "installation", "lib", "node_modules")
                if os.path.isdir(modules):
                    prefixes.append(modules)
            fnm_ms = os.environ.get("FNM_MULTISHELL_PATH", "")
            if fnm_ms:
                modules = os.path.join(fnm_ms, "lib", "node_modules")
                if os.path.isdir(modules):
                    prefixes.append(modules)
    # volta-managed
    volta_home = os.environ.get("VOLTA_HOME", os.path.expanduser("~/.volta"))
    if os.path.isdir(volta_home):
        volta_bin = os.path.join(volta_home, "tools", "image", "packages")
        if os.path.isdir(volta_bin):
            prefixes.append(volta_bin)
        volta_node = os.path.join(volta_home, "tools", "image", "node")
        if os.path.isdir(volta_node):
            try:
                versions = sorted(os.listdir(volta_node))
                if versions:
                    modules = os.path.join(volta_node, versions[-1], "lib", "node_modules")
                    if os.path.isdir(modules):
                        prefixes.append(modules)
            except OSError as e:
                log.debug("could not list volta node versions: %s", e)
    # System defaults
    prefixes.extend(
        [
            "/opt/homebrew/lib/node_modules",
            "/usr/local/lib/node_modules",
            "/usr/lib/node_modules",
            os.path.expanduser("~/.npm-global/lib/node_modules"),
        ]
    )
    if platform.system() == "Windows":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            prefixes.append(os.path.join(appdata, "npm", "node_modules"))
    return prefixes


_BREW_CELLAR_PATHS = [
    "/opt/homebrew/Cellar",
    "/usr/local/Cellar",
]


def scan_brew_package(client: ClientDef) -> DetectedClient | None:
    """Check if a homebrew formula is installed (macOS only)."""
    if not client.detect_brew or platform.system() != "Darwin":
        return None

    for cellar in _BREW_CELLAR_PATHS:
        formula_dir = os.path.join(cellar, client.detect_brew)
        if not os.path.isdir(formula_dir):
            continue
        try:
            versions = sorted(os.listdir(formula_dir))
            version = versions[-1] if versions else ""
            log.debug("brew formula found: %s@%s at %s", client.detect_brew, version, cellar)
            return DetectedClient(
                client_id=client.id,
                display_name=client.display_name,
                installed=True,
                version=version,
                install_method=InstallMethod.BREW,
                install_path=formula_dir,
                proxy_config_type=client.proxy_config.config_type.value,
                setup_instructions=client.proxy_config.setup_instructions,
                website=client.website,
            )
        except OSError as e:
            log.warning("could not list brew cellar for %s: %s — trying next cellar", client.detect_brew, e)
            continue
    return None


_NEOVIM_PLUGIN_DIRS = [
    "~/.local/share/nvim/lazy",
    "~/.local/share/nvim/plugged",
    "~/.local/share/nvim/site/pack/*/start",
    "~/.local/share/nvim/site/pack/*/opt",
]


def scan_neovim_plugin(client: ClientDef) -> DetectedClient | None:
    """Check if a Neovim plugin is installed across common plugin managers."""
    if not client.detect_neovim_plugin:
        return None

    for dir_pattern in _NEOVIM_PLUGIN_DIRS:
        expanded = os.path.expanduser(dir_pattern)
        if "*" in expanded:
            parent_dirs = glob.glob(expanded)
        else:
            parent_dirs = [expanded] if os.path.isdir(expanded) else []

        for parent in parent_dirs:
            plugin_dir = os.path.join(parent, client.detect_neovim_plugin)
            if os.path.isdir(plugin_dir):
                log.debug("Neovim plugin found: %s at %s", client.detect_neovim_plugin, plugin_dir)
                return DetectedClient(
                    client_id=client.id,
                    display_name=client.display_name,
                    installed=True,
                    install_method=InstallMethod.NEOVIM_PLUGIN,
                    install_path=plugin_dir,
                    proxy_config_type=client.proxy_config.config_type.value,
                    setup_instructions=client.proxy_config.setup_instructions,
                    website=client.website,
                )
    return None


def detect_version(client: ClientDef, detected: DetectedClient) -> str:
    """Detect version via --version command or macOS app bundle plist.

    Priority: existing version > command > app bundle plist.
    """
    if detected.version:
        return detected.version

    # Try --version command first
    if client.version_command:
        version = _version_from_command(client.version_command)
        if version:
            return version

    # Fallback: macOS app bundle plist (for GUI apps like Cursor, Windsurf)
    if platform.system() == "Darwin" and client.detect_app_name:
        version = _version_from_app_bundle(client.detect_app_name)
        if version:
            return version

    return ""


def _version_from_command(command: tuple[str, ...]) -> str:
    """Run a --version command and extract version string."""
    try:
        result = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = (result.stdout or "") + (result.stderr or "")
        match = VERSION_RE.search(output)
        if match:
            version = match.group(1)
            log.debug("version detected via command: %s → %s", command[0], version)
            return version
        log.debug("version command produced no match: %s → %r", command[0], output[:100])
    except FileNotFoundError:
        log.debug("version command not found: %s", command[0])
    except subprocess.TimeoutExpired:
        log.warning("version command timed out: %s", command[0])
    except OSError as e:
        log.warning("version command failed: %s — %s", command[0], e)
    return ""


def _version_from_app_bundle(app_name: str) -> str:
    """Read version from macOS app bundle Info.plist."""
    app_path = "/Applications/%s" % app_name
    if not os.path.isdir(app_path):
        return ""
    try:
        result = subprocess.run(
            ["defaults", "read", "%s/Contents/Info.plist" % app_path, "CFBundleShortVersionString"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            if version:
                log.debug("version detected via plist: %s → %s", app_name, version)
                return version
    except (OSError, subprocess.TimeoutExpired) as e:
        log.debug("plist version failed for %s: %s", app_name, e)
    return ""
