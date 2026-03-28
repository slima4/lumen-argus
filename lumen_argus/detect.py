"""Client auto-detection engine — scans for installed AI CLI agents.

Discovers installed AI coding tools via binary lookup, package managers,
IDE extensions, and app bundles. Checks proxy configuration status in
shell profiles and IDE settings.

All detection is read-only — never modifies files. Setup is in setup_wizard.py.
"""

import enum
import glob
import json
import logging
import os
import platform
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any

from lumen_argus.clients import CLIENT_REGISTRY, ClientDef

log = logging.getLogger("argus.detect")

# Env vars that route AI tools through the proxy
PROXY_ENV_VARS = ("ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "GEMINI_BASE_URL")

# Shell profile files to scan (in priority order per shell)
_SHELL_PROFILES = {
    "zsh": ("~/.zshrc", "~/.zshenv", "~/.zprofile"),
    "bash": ("~/.bashrc", "~/.bash_profile", "~/.profile"),
    "fish": ("~/.config/fish/config.fish",),
    "powershell": (),  # dynamically resolved via _get_powershell_profiles()
}


def _get_powershell_profiles() -> tuple[str, ...]:
    """Get PowerShell profile paths on Windows."""
    if platform.system() != "Windows":
        return ()
    # PowerShell 7 (pwsh) and Windows PowerShell 5.1
    docs = os.environ.get("USERPROFILE", os.path.expanduser("~"))
    return (
        os.path.join(docs, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1"),
        os.path.join(docs, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
    )


@dataclass(frozen=True)
class IDEVariant:
    """VS Code-like IDE variant with extension and settings paths."""

    name: str
    extensions: tuple[str, ...]
    settings: tuple[str, ...]


# VS Code variants and their extensions/settings paths
_VSCODE_VARIANTS: tuple[IDEVariant, ...] = (
    IDEVariant(
        name="VS Code",
        extensions=(
            "~/.vscode/extensions",
            "~/Library/Application Support/Code/User/extensions",
        ),
        settings=(
            "~/Library/Application Support/Code/User/settings.json",
            "~/.config/Code/User/settings.json",
        ),
    ),
    IDEVariant(
        name="VS Code Insiders",
        extensions=("~/.vscode-insiders/extensions",),
        settings=(
            "~/Library/Application Support/Code - Insiders/User/settings.json",
            "~/.config/Code - Insiders/User/settings.json",
        ),
    ),
    IDEVariant(
        name="VSCodium",
        extensions=("~/.vscode-oss/extensions",),
        settings=(
            "~/Library/Application Support/VSCodium/User/settings.json",
            "~/.config/VSCodium/User/settings.json",
        ),
    ),
    IDEVariant(
        name="Cursor",
        extensions=("~/.cursor/extensions",),
        settings=(
            "~/.cursor/User/settings.json",
            "~/Library/Application Support/Cursor/User/settings.json",
        ),
    ),
    IDEVariant(
        name="Windsurf",
        extensions=("~/.windsurf/extensions",),
        settings=(
            "~/.windsurf/User/settings.json",
            "~/Library/Application Support/Windsurf/User/settings.json",
        ),
    ),
)

# Windows-specific IDE paths (appended when on Windows)
_WINDOWS_VSCODE_VARIANTS: tuple[IDEVariant, ...] = (
    IDEVariant(
        name="VS Code (Windows)",
        extensions=("~/.vscode/extensions",),
        settings=("%APPDATA%/Code/User/settings.json",),
    ),
    IDEVariant(
        name="VS Code Insiders (Windows)",
        extensions=("~/.vscode-insiders/extensions",),
        settings=("%APPDATA%/Code - Insiders/User/settings.json",),
    ),
    IDEVariant(
        name="VSCodium (Windows)",
        extensions=("~/.vscode-oss/extensions",),
        settings=("%APPDATA%/VSCodium/User/settings.json",),
    ),
    IDEVariant(
        name="Cursor (Windows)",
        extensions=("~/.cursor/extensions",),
        settings=("%APPDATA%/Cursor/User/settings.json",),
    ),
    IDEVariant(
        name="Windsurf (Windows)",
        extensions=("~/.windsurf/extensions",),
        settings=("%APPDATA%/Windsurf/User/settings.json",),
    ),
)


def _get_vscode_variants() -> tuple[IDEVariant, ...]:
    """Get VS Code variants for the current platform."""
    if platform.system() == "Windows":
        # Expand %APPDATA% in Windows paths
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            expanded = []
            for v in _WINDOWS_VSCODE_VARIANTS:
                settings = tuple(s.replace("%APPDATA%", appdata) for s in v.settings)
                expanded.append(IDEVariant(name=v.name, extensions=v.extensions, settings=settings))
            return tuple(expanded) + _VSCODE_VARIANTS
    return _VSCODE_VARIANTS


_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[.-]\w+)?)")


def load_jsonc(path: str) -> dict[str, Any]:
    """Load a JSONC file (JSON with // comments). Returns parsed dict or empty dict on error."""
    expanded = os.path.expanduser(path)
    if not os.path.isfile(expanded):
        return {}
    try:
        with open(expanded, "r", encoding="utf-8") as f:
            lines = [line for line in f if not line.lstrip().startswith("//")]
        result: dict[str, Any] = json.loads("".join(lines))
        return result
    except json.JSONDecodeError as e:
        log.warning("invalid JSON in %s: %s", path, e)
        return {}
    except OSError as e:
        log.warning("could not read %s: %s", path, e)
        return {}


# Pre-compiled env var extraction patterns (one set per var)
_ENV_VAR_PATTERNS = {
    var: [
        re.compile(r"export\s+%s=[\"']?([^\s\"'#]+)" % re.escape(var)),
        re.compile(r"%s=[\"']?([^\s\"'#]+)" % re.escape(var)),
        re.compile(r"set\s+-x\s+%s\s+[\"']?([^\s\"'#]+)" % re.escape(var)),  # fish
        # PowerShell: $env:VAR = "value"
        re.compile(r"\$env:%s\s*=\s*[\"']?([^\s\"'#]+)" % re.escape(var)),
    ]
    for var in PROXY_ENV_VARS
}


# ---------------------------------------------------------------------------
# CI/CD environment detection
# ---------------------------------------------------------------------------

# Known CI/CD environments detected via env vars
_CI_ENVIRONMENTS = (
    ("GITHUB_ACTIONS", "github_actions", "GitHub Actions"),
    ("GITLAB_CI", "gitlab_ci", "GitLab CI"),
    ("CIRCLECI", "circleci", "CircleCI"),
    ("JENKINS_URL", "jenkins", "Jenkins"),
    ("TRAVIS", "travis_ci", "Travis CI"),
    ("BUILDKITE", "buildkite", "Buildkite"),
    ("CODEBUILD_BUILD_ID", "aws_codebuild", "AWS CodeBuild"),
    ("TF_BUILD", "azure_pipelines", "Azure Pipelines"),
    ("BITBUCKET_BUILD_NUMBER", "bitbucket_pipelines", "Bitbucket Pipelines"),
    ("TEAMCITY_VERSION", "teamcity", "TeamCity"),
)

# Container environments
_CONTAINER_ENVIRONMENTS = (
    ("KUBERNETES_SERVICE_HOST", "kubernetes", "Kubernetes"),
    # /.dockerenv file check handled in code
)


@dataclass
class CIEnvironment:
    """Detected CI/CD or container environment."""

    env_id: str = ""  # e.g., "github_actions", "kubernetes"
    display_name: str = ""  # e.g., "GitHub Actions"
    detected: bool = False
    details: dict[str, str] = field(default_factory=dict)  # extra info

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def detect_ci_environment() -> CIEnvironment | None:
    """Detect if running in a CI/CD or container environment.

    Returns CIEnvironment if detected, None otherwise.
    """
    # Check CI/CD platforms
    for env_var, env_id, display_name in _CI_ENVIRONMENTS:
        if os.environ.get(env_var):
            details: dict[str, str] = {}
            if env_id == "github_actions":
                details["repository"] = os.environ.get("GITHUB_REPOSITORY", "")
                details["workflow"] = os.environ.get("GITHUB_WORKFLOW", "")
                details["runner_os"] = os.environ.get("RUNNER_OS", "")
            elif env_id == "gitlab_ci":
                details["project"] = os.environ.get("CI_PROJECT_NAME", "")
                details["pipeline_id"] = os.environ.get("CI_PIPELINE_ID", "")
            log.debug("CI environment detected: %s", display_name)
            return CIEnvironment(env_id=env_id, display_name=display_name, detected=True, details=details)

    # Check container environments
    for env_var, env_id, display_name in _CONTAINER_ENVIRONMENTS:
        if os.environ.get(env_var):
            details = {}
            if env_id == "kubernetes":
                details["namespace"] = os.environ.get("KUBERNETES_NAMESPACE", "")
            log.debug("container environment detected: %s", display_name)
            return CIEnvironment(env_id=env_id, display_name=display_name, detected=True, details=details)

    # Check Docker (file-based)
    if os.path.exists("/.dockerenv"):
        log.debug("container environment detected: Docker")
        return CIEnvironment(env_id="docker", display_name="Docker", detected=True)

    # Generic CI flag (many CI systems set CI=true)
    if os.environ.get("CI", "").lower() in ("true", "1", "yes"):
        log.debug("generic CI environment detected via CI env var")
        return CIEnvironment(env_id="ci_generic", display_name="CI (generic)", detected=True)

    return None


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class InstallMethod(str, enum.Enum):
    """How a client was detected on the system."""

    BINARY = "binary"
    PIP = "pip"
    NPM = "npm"
    BREW = "brew"
    VSCODE_EXT = "vscode_ext"
    APP_BUNDLE = "app_bundle"
    JETBRAINS_PLUGIN = "jetbrains_plugin"
    NEOVIM_PLUGIN = "neovim_plugin"


@dataclass
class DetectedClient:
    """Result of detecting a single AI CLI agent."""

    client_id: str = ""
    display_name: str = ""
    installed: bool = False
    version: str = ""
    install_method: str = ""
    install_path: str = ""
    proxy_configured: bool = False
    proxy_url: str = ""
    proxy_config_location: str = ""
    env_var: str = ""
    setup_cmd: str = ""
    website: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DetectionReport:
    """Aggregate detection results for all agents."""

    clients: list[DetectedClient] = field(default_factory=list)
    shell_env_vars: dict[str, tuple[str, str, int]] = field(default_factory=dict)  # {var_name: (value, file, line_num)}
    platform: str = ""
    total_detected: int = 0
    total_configured: int = 0
    ci_environment: CIEnvironment | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "platform": self.platform,
            "total_detected": self.total_detected,
            "total_configured": self.total_configured,
            "clients": [c.to_dict() for c in self.clients],
            "shell_env_vars": {k: {"value": v[0], "file": v[1], "line": v[2]} for k, v in self.shell_env_vars.items()},
        }
        if self.ci_environment:
            result["ci_environment"] = self.ci_environment.to_dict()
        return result


# ---------------------------------------------------------------------------
# Scanner functions
# ---------------------------------------------------------------------------


def _scan_binary(client: ClientDef) -> DetectedClient | None:
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
                env_var=client.env_var,
                setup_cmd=client.setup_cmd,
                website=client.website,
            )
    return None


def _scan_pip_package(client: ClientDef) -> DetectedClient | None:
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
            env_var=client.env_var,
            setup_cmd=client.setup_cmd,
            website=client.website,
        )
    except ImportError:
        log.debug("importlib.metadata not available")
        return None
    except Exception as e:
        # PackageNotFoundError inherits from ModuleNotFoundError on Python 3.9+
        err_name = type(e).__name__
        if "NotFound" in err_name or "PackageNotFound" in err_name:
            log.debug("pip package %s not installed", client.detect_pip)
        else:
            log.warning("unexpected error checking pip package %s: %s", client.detect_pip, e, exc_info=True)
        return None


def _scan_vscode_extension(client: ClientDef) -> DetectedClient | None:
    """Check if a VS Code extension is installed across all VS Code variants."""
    if not client.detect_vscode_ext:
        return None
    ext_id_lower = client.detect_vscode_ext.lower()

    for variant in _get_vscode_variants():
        for ext_dir in variant.extensions:
            ext_dir = os.path.expanduser(ext_dir)
            if not os.path.isdir(ext_dir):
                continue
            # Extension dirs: <publisher>.<name>-<version>/
            pattern = os.path.join(ext_dir, "%s-*" % ext_id_lower)
            matches = glob.glob(pattern)
            if matches:
                # Take the newest version (last alphabetically)
                match_path = sorted(matches)[-1]
                dir_name = os.path.basename(match_path)
                # Extract version from dir name: github.copilot-1.200.0 → 1.200.0
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
                    env_var=client.env_var,
                    setup_cmd=client.setup_cmd,
                    website=client.website,
                )
    return None


def _scan_app_bundle(client: ClientDef) -> DetectedClient | None:
    """Check for macOS .app bundle in /Applications."""
    if not client.detect_app_name or platform.system() != "Darwin":
        return None
    app_path = "/Applications/%s" % client.detect_app_name
    if os.path.isdir(app_path):
        # Try to read version from Info.plist
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
            env_var=client.env_var,
            setup_cmd=client.setup_cmd,
            website=client.website,
        )
    return None


def _scan_jetbrains_plugin(client: ClientDef) -> DetectedClient | None:
    """Check for JetBrains IDE plugins."""
    if not client.detect_jetbrains_plugin:
        return None

    # JetBrains plugin dirs vary by product and OS
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

    # Search across all JetBrains products (IntelliJIdea, PyCharm, etc.)
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
                env_var=client.env_var,
                setup_cmd=client.setup_cmd,
                website=client.website,
            )
    return None


def _scan_npm_package(client: ClientDef) -> DetectedClient | None:
    """Check if an npm global package is installed by reading package.json."""
    if not client.detect_npm:
        return None

    # Common global node_modules locations
    npm_prefixes = []
    npm_root = os.environ.get("NPM_CONFIG_PREFIX", "")
    if npm_root:
        npm_prefixes.append(os.path.join(npm_root, "lib", "node_modules"))
    # nvm-managed
    nvm_dir = os.environ.get("NVM_DIR", os.path.expanduser("~/.nvm"))
    if os.path.isdir(nvm_dir):
        # Current node version's global modules
        current = os.path.join(nvm_dir, "current", "lib", "node_modules")
        if os.path.isdir(current):
            npm_prefixes.append(current)
    # fnm-managed (Fast Node Manager)
    fnm_dir = os.environ.get("FNM_DIR", "")
    if not fnm_dir:
        # Default fnm dirs per platform
        if platform.system() == "Darwin":
            fnm_dir = os.path.expanduser("~/Library/Application Support/fnm")
        else:
            fnm_dir = os.path.expanduser("~/.local/share/fnm")
    if os.path.isdir(fnm_dir):
        fnm_current = os.path.join(fnm_dir, "node-versions")
        if os.path.isdir(fnm_current):
            # fnm symlinks current version — check aliases/default
            fnm_default = os.path.join(fnm_dir, "aliases", "default")
            if os.path.isdir(fnm_default):
                modules = os.path.join(fnm_default, "installation", "lib", "node_modules")
                if os.path.isdir(modules):
                    npm_prefixes.append(modules)
            # Also check FNM_MULTISHELL_PATH (set when fnm env is active)
            fnm_ms = os.environ.get("FNM_MULTISHELL_PATH", "")
            if fnm_ms:
                modules = os.path.join(fnm_ms, "lib", "node_modules")
                if os.path.isdir(modules):
                    npm_prefixes.append(modules)
    # volta-managed
    volta_home = os.environ.get("VOLTA_HOME", os.path.expanduser("~/.volta"))
    if os.path.isdir(volta_home):
        # volta installs global packages in its own tool chain
        volta_bin = os.path.join(volta_home, "tools", "image", "packages")
        if os.path.isdir(volta_bin):
            npm_prefixes.append(volta_bin)
        # Also check node global modules under volta
        volta_node = os.path.join(volta_home, "tools", "image", "node")
        if os.path.isdir(volta_node):
            try:
                versions = sorted(os.listdir(volta_node))
                if versions:
                    modules = os.path.join(volta_node, versions[-1], "lib", "node_modules")
                    if os.path.isdir(modules):
                        npm_prefixes.append(modules)
            except OSError as e:
                log.debug("could not list volta node versions: %s", e)
    # System defaults
    npm_prefixes.extend(
        [
            "/opt/homebrew/lib/node_modules",  # Homebrew Node on Apple Silicon
            "/usr/local/lib/node_modules",
            "/usr/lib/node_modules",
            os.path.expanduser("~/.npm-global/lib/node_modules"),
        ]
    )
    # Windows npm global
    if platform.system() == "Windows":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            npm_prefixes.append(os.path.join(appdata, "npm", "node_modules"))

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
            env_var=client.env_var,
            setup_cmd=client.setup_cmd,
            website=client.website,
        )
    return None


_BREW_CELLAR_PATHS = [
    "/opt/homebrew/Cellar",  # Apple Silicon
    "/usr/local/Cellar",  # Intel
]


def _scan_brew_package(client: ClientDef) -> DetectedClient | None:
    """Check if a homebrew formula is installed (macOS only)."""
    if not client.detect_brew or platform.system() != "Darwin":
        return None

    cellar_paths = _BREW_CELLAR_PATHS
    for cellar in cellar_paths:
        formula_dir = os.path.join(cellar, client.detect_brew)
        if not os.path.isdir(formula_dir):
            continue
        # Version is the subdirectory name (e.g., /opt/homebrew/Cellar/aider/0.50.1/)
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
                env_var=client.env_var,
                setup_cmd=client.setup_cmd,
                website=client.website,
            )
        except OSError as e:
            log.warning("could not list brew cellar for %s: %s — trying next cellar", client.detect_brew, e)
            continue
    return None


# Neovim plugin manager paths (checked in order)
_NEOVIM_PLUGIN_DIRS = [
    "~/.local/share/nvim/lazy",  # lazy.nvim (most popular)
    "~/.local/share/nvim/plugged",  # vim-plug
    "~/.local/share/nvim/site/pack/*/start",  # native packages (glob)
    "~/.local/share/nvim/site/pack/*/opt",  # native opt packages
]


def _scan_neovim_plugin(client: ClientDef) -> DetectedClient | None:
    """Check if a Neovim plugin is installed across common plugin managers."""
    if not client.detect_neovim_plugin:
        return None

    for dir_pattern in _NEOVIM_PLUGIN_DIRS:
        expanded = os.path.expanduser(dir_pattern)
        if "*" in expanded:
            # Glob for native pack dirs
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
                    env_var=client.env_var,
                    setup_cmd=client.setup_cmd,
                    website=client.website,
                )
    return None


def _detect_version(client: ClientDef, detected: DetectedClient) -> str:
    """Run --version command to get precise version. Returns version string or empty."""
    if not client.version_command or detected.version:
        return detected.version
    try:
        result = subprocess.run(
            list(client.version_command),
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = (result.stdout or "") + (result.stderr or "")
        match = _VERSION_RE.search(output)
        if match:
            version = match.group(1)
            log.debug("version detected via command: %s → %s", client.version_command[0], version)
            return version
        log.debug("version command produced no match: %s → %r", client.version_command[0], output[:100])
    except FileNotFoundError:
        log.debug("version command not found: %s", client.version_command[0])
    except subprocess.TimeoutExpired:
        log.warning("version command timed out: %s", client.version_command[0])
    except OSError as e:
        log.warning("version command failed: %s — %s", client.version_command[0], e)
    return ""


# ---------------------------------------------------------------------------
# Shell profile scanning
# ---------------------------------------------------------------------------


def _scan_shell_profiles(proxy_url: str = "") -> dict[str, tuple[str, str, int]]:
    """Scan shell profile files for proxy env vars.

    Returns {var_name: (value, file_path, line_number)} for each found var.
    """
    found: dict[str, tuple[str, str, int]] = {}
    current_shell = os.path.basename(os.environ.get("SHELL", ""))

    # Determine which profiles to scan (current shell first, then others)
    profiles_to_scan: list[str] = []
    if current_shell in _SHELL_PROFILES:
        profiles_to_scan.extend(_SHELL_PROFILES[current_shell])
    for shell, profiles in _SHELL_PROFILES.items():
        if shell != current_shell:
            profiles_to_scan.extend(profiles)
    # Add PowerShell profiles on Windows
    if platform.system() == "Windows":
        profiles_to_scan.extend(_get_powershell_profiles())

    for profile_path in profiles_to_scan:
        expanded = os.path.expanduser(profile_path)
        if not os.path.isfile(expanded):
            continue
        try:
            with open(expanded, "r", encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    for var in PROXY_ENV_VARS:
                        # Match: export VAR=value, VAR=value, set -x VAR value (fish)
                        if var in stripped:
                            # Extract value
                            value = _extract_env_value(stripped, var)
                            if value and var not in found:
                                found[var] = (value, profile_path, line_num)
                                log.debug("shell env found: %s=%s in %s:%d", var, value, profile_path, line_num)
        except OSError as e:
            log.warning("could not read shell profile %s: %s", profile_path, e)
    return found


def _extract_env_value(line: str, var_name: str) -> str:
    """Extract env var value from a shell profile line."""
    compiled = _ENV_VAR_PATTERNS.get(var_name)
    if not compiled:
        return ""
    for pattern in compiled:
        match = pattern.search(line)
        if match:
            return match.group(1)
    return ""


# ---------------------------------------------------------------------------
# IDE settings scanning
# ---------------------------------------------------------------------------


def _build_settings_cache() -> dict[str, tuple[dict[str, Any], str]]:
    """Load and parse all existing IDE settings files once. Returns {expanded_path: (settings, path)}."""
    cache: dict[str, tuple[dict[str, Any], str]] = {}
    for variant in _get_vscode_variants():
        for settings_path in variant.settings:
            expanded = os.path.expanduser(settings_path)
            if expanded in cache:
                continue
            settings = load_jsonc(expanded)
            if settings:
                cache[expanded] = (settings, settings_path)
                log.debug("cached IDE settings: %s (%d keys)", settings_path, len(settings))
    return cache


def _check_ide_proxy_settings(
    client: ClientDef, proxy_url: str = "", settings_cache: dict[str, tuple[dict[str, Any], str]] | None = None
) -> tuple[bool, str, str] | None:
    """Check if IDE settings have proxy configured for this client.

    Returns (is_configured, proxy_value, settings_file) or None if no settings found.
    """
    if not client.proxy_settings_key:
        return None

    if settings_cache is None:
        settings_cache = _build_settings_cache()

    for settings, settings_path in settings_cache.values():
        value: str = str(settings.get(client.proxy_settings_key, ""))
        if value:
            is_match = bool(proxy_url and proxy_url in value)
            log.debug(
                "IDE setting found: %s=%s in %s (match=%s)",
                client.proxy_settings_key,
                value,
                settings_path,
                is_match,
            )
            return is_match, value, settings_path
    return None


# ---------------------------------------------------------------------------
# Main detection API
# ---------------------------------------------------------------------------


def detect_installed_clients(
    proxy_url: str = "http://localhost:8080",
    include_versions: bool = False,
    extra_clients: list[ClientDef] | None = None,
) -> DetectionReport:
    """Scan the system for installed AI CLI agents and their proxy configuration status.

    Args:
        proxy_url: Expected proxy URL to check against configured values.
        include_versions: If True, run --version commands (slower).
        extra_clients: Additional ClientDef entries from Pro extensions.

    Returns:
        DetectionReport with all detection results.
    """
    log.info("starting client detection (versions=%s, proxy_url=%s)", include_versions, proxy_url)

    clients_to_scan = list(CLIENT_REGISTRY)
    if extra_clients:
        clients_to_scan.extend(extra_clients)

    # Scan shell profiles and IDE settings once (shared across all clients)
    shell_env = _scan_shell_profiles(proxy_url)
    settings_cache = _build_settings_cache()

    results = []
    for client in clients_to_scan:
        detected = _detect_single_client(client, shell_env, proxy_url, include_versions, settings_cache)
        results.append(detected)

    total_detected = sum(1 for r in results if r.installed)
    total_configured = sum(1 for r in results if r.installed and r.proxy_configured)

    # Detect CI/CD environment
    ci_env = detect_ci_environment()

    report = DetectionReport(
        clients=results,
        shell_env_vars=shell_env,
        platform="%s %s" % (platform.system(), platform.machine()),
        total_detected=total_detected,
        total_configured=total_configured,
        ci_environment=ci_env,
    )

    log.info(
        "detection complete: %d/%d tools detected, %d/%d configured for proxy",
        total_detected,
        len(clients_to_scan),
        total_configured,
        total_detected,
    )
    return report


def _detect_single_client(
    client: ClientDef,
    shell_env: dict[str, tuple[str, str, int]],
    proxy_url: str,
    include_versions: bool,
    settings_cache: dict[str, tuple[dict[str, Any], str]] | None = None,
) -> DetectedClient:
    """Run all scanners for a single client, merge results."""
    # Try each scanner in order — first match wins for install detection
    detected = None
    scanners = [
        _scan_binary,
        _scan_pip_package,
        _scan_npm_package,
        _scan_brew_package,
        _scan_vscode_extension,
        _scan_app_bundle,
        _scan_jetbrains_plugin,
        _scan_neovim_plugin,
    ]
    for scanner in scanners:
        try:
            result = scanner(client)
            if result:
                detected = result
                break
        except Exception as e:
            log.error("scanner failed for %s: %s", client.id, e, exc_info=True)

    if detected is None:
        return DetectedClient(
            client_id=client.id,
            display_name=client.display_name,
            env_var=client.env_var,
            setup_cmd=client.setup_cmd,
            website=client.website,
        )

    # Version detection (optional, runs subprocess)
    if include_versions:
        detected.version = _detect_version(client, detected)

    # Check proxy configuration from shell env vars
    env_var = client.env_var
    if env_var in shell_env:
        value, file_path, line_num = shell_env[env_var]
        detected.proxy_url = value
        detected.proxy_config_location = "%s:%d" % (file_path, line_num)
        detected.proxy_configured = bool(proxy_url and proxy_url in value)

    # Check IDE proxy settings (for extension-based tools)
    if not detected.proxy_configured and client.proxy_settings_key:
        ide_result = _check_ide_proxy_settings(client, proxy_url, settings_cache)
        if ide_result:
            is_configured, value, settings_file = ide_result
            detected.proxy_url = value
            detected.proxy_config_location = settings_file
            detected.proxy_configured = is_configured

    return detected
