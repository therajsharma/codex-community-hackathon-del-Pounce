#!/usr/bin/env python3
"""Install or refresh the local Pounce plugin for Codex."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable

from pounce_runtime import (
    agents_block_text,
    load_json_file,
    plugin_root_from_script,
    render_workspace_config_toml,
    render_workspace_hooks,
    replace_managed_block,
    validate_workspace_path_for_write,
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


def json_text(payload: Any) -> str:
    return json.dumps(payload, indent=2) + "\n"


def write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=str(path.parent))
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        temp_path.replace(path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def write_json_atomic(path: Path, payload: Any) -> None:
    write_text_atomic(path, json_text(payload))


def remove_path(path: Path) -> None:
    if not path.exists():
        return
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def reserve_backup_path(parent: Path, prefix: str) -> Path:
    parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=prefix, dir=str(parent))
    os.close(fd)
    path = Path(temp_name)
    path.unlink(missing_ok=True)
    return path


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
    write_json_atomic(installed_root / ".mcp.json", payload)


def write_installed_hooks(installed_root: Path) -> None:
    write_json_atomic(installed_root / "hooks.json", render_workspace_hooks(installed_root))


def load_marketplace(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "name": MARKETPLACE_NAME,
            "interface": {"displayName": MARKETPLACE_DISPLAY_NAME},
            "plugins": [],
        }
    return json.loads(path.read_text(encoding="utf-8"))


def render_marketplace_payload(existing_payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(existing_payload)
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
    return payload


def update_marketplace(path: Path) -> None:
    write_json_atomic(path, render_marketplace_payload(load_marketplace(path)))


def render_agents_md(existing: str) -> str:
    return replace_managed_block(existing, agents_block_text())


def update_agents_md(workspace: Path) -> None:
    validate_workspace_path_for_write(workspace, plugin_root=plugin_root_from_script(__file__), allowed_root=workspace)
    agents_path = workspace / "AGENTS.md"
    existing = agents_path.read_text(encoding="utf-8") if agents_path.exists() else ""
    write_text_atomic(agents_path, render_agents_md(existing))


def render_workspace_hook_payload(workspace: Path, installed_root: Path) -> dict[str, Any]:
    hooks_path = workspace / ".codex" / "hooks.json"
    existing_payload = load_json_file(hooks_path, default={})
    if not isinstance(existing_payload, dict):
        existing_payload = {}
    return render_workspace_hooks(installed_root, existing_payload)


def write_workspace_hooks(workspace: Path, installed_root: Path) -> None:
    validate_workspace_path_for_write(workspace, plugin_root=plugin_root_from_script(__file__), allowed_root=workspace)
    codex_dir = workspace / ".codex"
    hooks_path = codex_dir / "hooks.json"
    config_path = codex_dir / "config.toml"
    write_json_atomic(hooks_path, render_workspace_hook_payload(workspace, installed_root))
    existing_config = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    write_text_atomic(config_path, render_workspace_config_toml(existing_config))


def stage_plugin_tree(source_root: Path, installed_root: Path) -> Path:
    installed_root.parent.mkdir(parents=True, exist_ok=True)
    stage_root = Path(tempfile.mkdtemp(prefix=f"{PLUGIN_NAME}.stage-", dir=str(installed_root.parent)))
    shutil.rmtree(stage_root)
    shutil.copytree(source_root, stage_root)
    write_installed_mcp(stage_root)
    write_installed_hooks(stage_root)
    return stage_root


class InstallTransaction:
    def __init__(self) -> None:
        self._rollback_actions: list[Callable[[], None]] = []
        self._cleanup_paths: list[Path] = []

    def write_file(self, path: Path, content: str) -> bool:
        existing = path.read_text(encoding="utf-8") if path.exists() else None
        if existing == content:
            return False
        self._backup_file(path)
        write_text_atomic(path, content)
        return True

    def replace_directory(self, staged_root: Path, installed_root: Path) -> None:
        backup_root: Path | None = None
        if installed_root.exists():
            backup_root = reserve_backup_path(installed_root.parent, f".{installed_root.name}.pounce-backup-")
            installed_root.replace(backup_root)
            self._cleanup_paths.append(backup_root)
        self._rollback_actions.append(self._rollback_directory(installed_root, backup_root))
        staged_root.replace(installed_root)

    def rollback(self) -> None:
        errors: list[Exception] = []
        for action in reversed(self._rollback_actions):
            try:
                action()
            except Exception as exc:
                errors.append(exc)
        if errors:
            raise errors[0]

    def cleanup(self) -> None:
        for path in reversed(self._cleanup_paths):
            remove_path(path)

    def _backup_file(self, path: Path) -> None:
        if not path.exists():
            self._rollback_actions.append(lambda target=path: remove_path(target))
            return
        backup_path = reserve_backup_path(path.parent, f".{path.name}.pounce-backup-")
        shutil.copy2(path, backup_path)
        self._cleanup_paths.append(backup_path)

        def restore_file(target: Path = path, backup: Path = backup_path) -> None:
            remove_path(target)
            backup.replace(target)

        self._rollback_actions.append(restore_file)

    @staticmethod
    def _rollback_directory(installed_root: Path, backup_root: Path | None) -> Callable[[], None]:
        def restore() -> None:
            remove_path(installed_root)
            if backup_root is not None and backup_root.exists():
                backup_root.replace(installed_root)

        return restore


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
    stage_root = stage_plugin_tree(source_root, installed_root)
    transaction = InstallTransaction()

    try:
        transaction.replace_directory(stage_root, installed_root)
        transaction.write_file(marketplace_path, json_text(render_marketplace_payload(load_marketplace(marketplace_path))))

        agents_path = workspace / "AGENTS.md"
        existing_agents = agents_path.read_text(encoding="utf-8") if agents_path.exists() else ""
        transaction.write_file(agents_path, render_agents_md(existing_agents))

        if not args.no_workspace_hooks:
            hooks_path = workspace / ".codex" / "hooks.json"
            config_path = workspace / ".codex" / "config.toml"
            transaction.write_file(hooks_path, json_text(render_workspace_hook_payload(workspace, installed_root)))
            existing_config = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
            transaction.write_file(config_path, render_workspace_config_toml(existing_config))
    except (Exception, KeyboardInterrupt):
        transaction.rollback()
        raise
    finally:
        remove_path(stage_root)

    transaction.cleanup()

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
