#!/usr/bin/env python3
"""Install or refresh the local Pounce plugin for Codex."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from pounce_runtime import (
    agents_block_text,
    ensure_workspace_config_toml,
    load_json_file,
    plugin_root_from_script,
    render_workspace_hooks,
    replace_managed_block,
    validate_workspace_path_for_write,
    write_json,
)


MARKETPLACE_NAME = "local-security-plugins"
MARKETPLACE_DISPLAY_NAME = "Local Security Plugins"
PLUGIN_NAME = "pounce"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install or refresh the local Pounce plugin.")
    parser.add_argument(
        "--workspace",
        default=str(Path.cwd()),
        help="Workspace root whose AGENTS.md should be updated.",
    )
    parser.add_argument(
        "--no-workspace-hooks",
        action="store_true",
        help="Skip generating workspace .codex/hooks.json and .codex/config.toml.",
    )
    return parser.parse_args()


def copy_plugin_tree(source_root: Path, installed_root: Path) -> None:
    if source_root.resolve() == installed_root.resolve():
        return
    if installed_root.exists():
        shutil.rmtree(installed_root)
    installed_root.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source_root, installed_root)


def write_installed_mcp(installed_root: Path) -> None:
    server_script = installed_root / "scripts" / "pounce_mcp_server.py"
    payload = {
        "mcpServers": {
            "pounce": {
                "command": "python3",
                "args": [str(server_script)],
            }
        }
    }
    write_json(installed_root / ".mcp.json", payload)


def write_installed_hooks(installed_root: Path) -> None:
    write_json(installed_root / "hooks.json", render_workspace_hooks(installed_root))


def load_marketplace(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "name": MARKETPLACE_NAME,
            "interface": {"displayName": MARKETPLACE_DISPLAY_NAME},
            "plugins": [],
        }
    return json.loads(path.read_text(encoding="utf-8"))


def update_marketplace(path: Path) -> None:
    payload = load_marketplace(path)
    if "interface" not in payload or not isinstance(payload["interface"], dict):
        payload["interface"] = {"displayName": MARKETPLACE_DISPLAY_NAME}
    payload.setdefault("name", MARKETPLACE_NAME)
    payload.setdefault("plugins", [])

    entry = {
        "name": PLUGIN_NAME,
        "source": {"source": "local", "path": "./.codex/plugins/pounce"},
        "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
        "category": "Coding",
    }

    replaced = False
    for index, plugin in enumerate(payload["plugins"]):
        if isinstance(plugin, dict) and plugin.get("name") == PLUGIN_NAME:
            payload["plugins"][index] = entry
            replaced = True
            break
    if not replaced:
        payload["plugins"].append(entry)

    write_json(path, payload)


def update_agents_md(workspace: Path) -> None:
    validate_workspace_path_for_write(workspace, plugin_root=plugin_root_from_script(__file__), allowed_root=workspace)
    agents_path = workspace / "AGENTS.md"
    existing = agents_path.read_text(encoding="utf-8") if agents_path.exists() else ""
    updated = replace_managed_block(existing, agents_block_text())
    agents_path.write_text(updated, encoding="utf-8")


def write_workspace_hooks(workspace: Path, installed_root: Path) -> None:
    validate_workspace_path_for_write(workspace, plugin_root=plugin_root_from_script(__file__), allowed_root=workspace)
    codex_dir = workspace / ".codex"
    codex_dir.mkdir(parents=True, exist_ok=True)
    hooks_path = codex_dir / "hooks.json"
    existing_payload = load_json_file(hooks_path, default={})
    if not isinstance(existing_payload, dict):
        existing_payload = {}
    write_json(hooks_path, render_workspace_hooks(installed_root, existing_payload))
    ensure_workspace_config_toml(codex_dir / "config.toml")


def main() -> int:
    args = parse_args()
    source_root = plugin_root_from_script(__file__)
    workspace = validate_workspace_path_for_write(
        Path(args.workspace),
        plugin_root=source_root,
        allowed_root=Path(args.workspace).expanduser().resolve(),
    )
    installed_root = Path.home() / ".codex" / "plugins" / PLUGIN_NAME
    marketplace_path = Path.home() / ".agents" / "plugins" / "marketplace.json"

    copy_plugin_tree(source_root, installed_root)
    write_installed_mcp(installed_root)
    write_installed_hooks(installed_root)
    update_marketplace(marketplace_path)
    update_agents_md(workspace)
    if not args.no_workspace_hooks:
        write_workspace_hooks(workspace, installed_root)

    print(f"Synced source plugin to: {installed_root}")
    print(f"Updated marketplace: {marketplace_path}")
    print(f"Updated workspace policy: {workspace / 'AGENTS.md'}")
    if not args.no_workspace_hooks:
        print(f"Updated workspace hook config: {workspace / '.codex' / 'hooks.json'}")
        print(f"Updated workspace config: {workspace / '.codex' / 'config.toml'}")

    print("Next steps:")
    print("1. Restart Codex.")
    print("2. Open the plugin directory and install or enable Pounce from the local marketplace.")
    print("3. Use pounce.vet before dependency-affecting changes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
