"""Top-level ``run_setup`` — detect tools and configure proxy routing."""

from __future__ import annotations

import logging

from lumen_argus_core.detect import detect_installed_clients
from lumen_argus_core.setup import env_file as _env_file
from lumen_argus_core.setup._models import SetupChange
from lumen_argus_core.setup._prompts import _prompt_yes
from lumen_argus_core.setup.env_file import add_env_to_shell_profile
from lumen_argus_core.setup.forward_proxy import _setup_forward_proxy
from lumen_argus_core.setup.ide import _find_ide_settings, update_ide_settings
from lumen_argus_core.setup.manifest import _detect_shell_profile, _save_manifest
from lumen_argus_core.setup.opencode import configure_opencode

log = logging.getLogger("argus.setup.orchestrator")


def run_setup(
    proxy_url: str = "http://localhost:8080",
    client_id: str = "",
    non_interactive: bool = False,
    dry_run: bool = False,
) -> list[SetupChange]:
    """Run the setup wizard — detect tools and configure proxy routing.

    Args:
        proxy_url: Proxy URL to configure (default localhost:8080).
        client_id: Configure only this client (empty = all detected).
        non_interactive: Auto-configure without prompting.
        dry_run: Show what would change without modifying files.
    """
    log.info(
        "setup wizard started (proxy=%s, client=%s, interactive=%s, dry_run=%s)",
        proxy_url,
        client_id or "all",
        not non_interactive,
        dry_run,
    )

    report = detect_installed_clients(proxy_url=proxy_url)

    targets = [c for c in report.clients if c.installed and not c.proxy_configured]
    if client_id:
        targets = [c for c in targets if c.client_id == client_id]

    if not targets:
        already_configured = [c for c in report.clients if c.installed and c.proxy_configured]
        if already_configured:
            print("All %d detected tools are already configured for %s." % (len(already_configured), proxy_url))
        elif not any(c.installed for c in report.clients):
            print("No AI tools detected on this machine.")
            print("Run 'lumen-argus clients' to see supported tools and install instructions.")
        else:
            print("All detected tools are already configured.")
        return []

    print("Found %d tool(s) needing configuration:\n" % len(targets))
    for t in targets:
        ver = " %s" % t.version if t.version else ""
        print("  %s%s (%s)" % (t.display_name, ver, t.install_method))

    changes: list[SetupChange] = []
    profile_path = _detect_shell_profile()

    for target in targets:
        print("\n-- %s %s" % (target.display_name, "-" * (40 - len(target.display_name))))

        from lumen_argus_core.clients import ProxyConfigType, get_client_by_id

        client_def = get_client_by_id(target.client_id)
        if not client_def:
            log.warning("no client def for %s, skipping", target.client_id)
            continue

        pc = client_def.proxy_config

        if pc.config_type == ProxyConfigType.ENV_VAR:
            if non_interactive or _prompt_yes("  Add '%s=%s' to env file?" % (pc.env_var, proxy_url)):
                change = add_env_to_shell_profile(
                    pc.env_var, proxy_url, target.client_id, profile_path, dry_run=dry_run
                )
                if change:
                    changes.append(change)
                    if not dry_run:
                        print("  Added to %s" % _env_file._ENV_FILE)
                else:
                    print("  Skipped (already set)")

            # OpenCode: also configure per-provider baseURLs in opencode.json.
            if target.client_id == "opencode":
                oc_change = configure_opencode(proxy_url, dry_run=dry_run)
                if oc_change:
                    changes.append(oc_change)
                    if not dry_run:
                        from lumen_argus_core.opencode_providers import OPENCODE_CONFIG_PATH

                        print("  Configured all providers in %s" % OPENCODE_CONFIG_PATH)

        elif pc.config_type == ProxyConfigType.IDE_SETTINGS:
            settings_file = _find_ide_settings(target.install_path)
            if settings_file:
                if non_interactive or _prompt_yes(
                    "  Set '%s': '%s' in %s?" % (pc.ide_settings_key, proxy_url, settings_file)
                ):
                    change = update_ide_settings(
                        settings_file, pc.ide_settings_key, proxy_url, target.client_id, dry_run=dry_run
                    )
                    if change:
                        changes.append(change)
                        if not dry_run:
                            print("  Updated %s" % settings_file)
            else:
                print("  Could not find IDE settings file.")
                print("  %s" % pc.setup_instructions)

        elif pc.config_type == ProxyConfigType.CONFIG_FILE:
            print("  %s" % pc.setup_instructions)

        elif pc.config_type == ProxyConfigType.MANUAL:
            if pc.forward_proxy:
                from lumen_argus_core.forward_proxy import ForwardProxyUnavailable

                try:
                    fp_changes = _setup_forward_proxy(target, profile_path, non_interactive, dry_run)
                except ForwardProxyUnavailable as exc:
                    # Pointer already printed inside _setup_forward_proxy —
                    # continue to the next tool rather than abort the whole run.
                    log.info("skipping forward-proxy tool %s: %s", target.client_id, exc)
                    continue
                changes.extend(fp_changes)
            else:
                print("  Requires manual configuration:")
                print("  %s" % pc.setup_instructions)

        elif pc.config_type == ProxyConfigType.UNSUPPORTED:
            print("  Reverse proxy not supported for this tool.")
            print("  %s" % pc.setup_instructions)

    if changes and not dry_run:
        _save_manifest(changes)
        print("\n%d tool(s) configured. Open a new terminal to apply." % len(changes))
    elif dry_run and changes:
        print("\n[dry-run] %d change(s) would be made." % len(changes))
    elif not changes:
        print("\nNo changes made.")

    return changes
