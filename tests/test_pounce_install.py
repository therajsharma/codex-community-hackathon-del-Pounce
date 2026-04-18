import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = REPO_ROOT / "plugins" / "pounce"
SCRIPTS_ROOT = PLUGIN_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import install_local  # noqa: E402


class PounceInstallTests(unittest.TestCase):
    def test_main_writes_workspace_hooks_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as home_dir, tempfile.TemporaryDirectory() as workspace_dir:
            fake_home = Path(home_dir)
            workspace = Path(workspace_dir)
            with mock.patch.object(Path, "home", return_value=fake_home), mock.patch.object(
                sys,
                "argv",
                ["install_local.py", "--workspace", str(workspace)],
            ):
                exit_code = install_local.main()
            hooks_exists = (workspace / ".codex" / "hooks.json").exists()
            config_exists = (workspace / ".codex" / "config.toml").exists()
        self.assertEqual(exit_code, 0)
        self.assertTrue(hooks_exists)
        self.assertTrue(config_exists)

    def test_workspace_hook_merge_preserves_existing_hooks_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            installed_root = workspace / "installed-plugin"
            (installed_root / "scripts").mkdir(parents=True, exist_ok=True)
            (workspace / ".codex").mkdir(parents=True, exist_ok=True)
            (workspace / ".codex" / "hooks.json").write_text(
                json.dumps(
                    {
                        "hooks": {
                            "PreToolUse": [
                                {
                                    "matcher": "Bash",
                                    "hooks": [
                                        {
                                            "type": "command",
                                            "command": "echo existing",
                                            "statusMessage": "Existing hook",
                                        }
                                    ],
                                }
                            ],
                            "PostToolUse": [{"matcher": "Write", "hooks": [{"type": "command", "command": "echo post"}]}],
                        }
                    }
                ),
                encoding="utf-8",
            )
            install_local.write_workspace_hooks(workspace, installed_root)
            install_local.write_workspace_hooks(workspace, installed_root)

            payload = json.loads((workspace / ".codex" / "hooks.json").read_text(encoding="utf-8"))

        pre_tool_use = payload["hooks"]["PreToolUse"]
        bash_entry = next(entry for entry in pre_tool_use if entry["matcher"] == "Bash")
        commands = [hook["command"] for hook in bash_entry["hooks"]]
        self.assertIn("echo existing", commands)
        self.assertEqual(sum("pounce_hook.py" in command for command in commands), 1)
        for event_name in ("UserPromptSubmit", "Stop"):
            self.assertIn(event_name, payload["hooks"])
            self.assertEqual(len(payload["hooks"][event_name]), 1)
            event_hooks = payload["hooks"][event_name][0]["hooks"]
            self.assertEqual(sum("pounce_hook.py" in hook["command"] for hook in event_hooks), 1)
        self.assertIn("PostToolUse", payload["hooks"])

    def test_workspace_config_is_preserved_when_hooks_are_written(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            installed_root = workspace / "installed-plugin"
            (installed_root / "scripts").mkdir(parents=True, exist_ok=True)
            (workspace / ".codex").mkdir(parents=True, exist_ok=True)
            (workspace / ".codex" / "config.toml").write_text(
                "[model]\nname = \"gpt-5.4\"\n\n[features]\ncodex_hooks = false\nother_flag = true\n",
                encoding="utf-8",
            )

            install_local.write_workspace_hooks(workspace, installed_root)

            content = (workspace / ".codex" / "config.toml").read_text(encoding="utf-8")

        self.assertIn("[model]", content)
        self.assertIn("name = \"gpt-5.4\"", content)
        self.assertIn("other_flag = true", content)
        self.assertIn("codex_hooks = true", content)
        self.assertEqual(content.count("[features]"), 1)

    def test_main_is_idempotent_for_agents_and_marketplace(self) -> None:
        with tempfile.TemporaryDirectory() as home_dir, tempfile.TemporaryDirectory() as workspace_dir:
            fake_home = Path(home_dir)
            workspace = Path(workspace_dir)
            (workspace / "AGENTS.md").write_text("# Workspace\n", encoding="utf-8")

            argv = ["install_local.py", "--workspace", str(workspace)]
            with mock.patch.object(Path, "home", return_value=fake_home), mock.patch.object(sys, "argv", argv):
                install_local.main()
            with mock.patch.object(Path, "home", return_value=fake_home), mock.patch.object(sys, "argv", argv):
                install_local.main()

            agents_text = (workspace / "AGENTS.md").read_text(encoding="utf-8")
            marketplace = json.loads(
                (fake_home / ".agents" / "plugins" / "marketplace.json").read_text(encoding="utf-8")
            )

        self.assertEqual(agents_text.count("BEGIN POUNCE MANAGED BLOCK"), 1)
        self.assertEqual(sum(plugin["name"] == "pounce" for plugin in marketplace["plugins"]), 1)

    def test_main_rolls_back_existing_files_on_keyboard_interrupt(self) -> None:
        with tempfile.TemporaryDirectory() as home_dir, tempfile.TemporaryDirectory() as workspace_dir:
            fake_home = Path(home_dir)
            workspace = Path(workspace_dir)
            installed_root = fake_home / ".codex" / "plugins" / "pounce"
            marketplace_path = fake_home / ".agents" / "plugins" / "marketplace.json"
            hooks_path = workspace / ".codex" / "hooks.json"
            config_path = workspace / ".codex" / "config.toml"
            agents_path = workspace / "AGENTS.md"

            (installed_root / "scripts").mkdir(parents=True, exist_ok=True)
            (installed_root / "scripts" / "marker.txt").write_text("old-plugin\n", encoding="utf-8")
            marketplace_path.parent.mkdir(parents=True, exist_ok=True)
            marketplace_path.write_text(json.dumps({"plugins": [{"name": "existing"}]}) + "\n", encoding="utf-8")
            hooks_path.parent.mkdir(parents=True, exist_ok=True)
            hooks_path.write_text(json.dumps({"hooks": {"PostToolUse": []}}) + "\n", encoding="utf-8")
            config_path.write_text("[features]\ncodex_hooks = false\n", encoding="utf-8")
            agents_path.write_text("# Existing workspace policy\n", encoding="utf-8")

            original_write_file = install_local.InstallTransaction.write_file

            def interrupt_after_agents(self: install_local.InstallTransaction, path: Path, content: str) -> bool:
                changed = original_write_file(self, path, content)
                if path.name == "AGENTS.md":
                    raise KeyboardInterrupt()
                return changed

            argv = ["install_local.py", "--workspace", str(workspace)]
            with (
                mock.patch.object(Path, "home", return_value=fake_home),
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(install_local.InstallTransaction, "write_file", new=interrupt_after_agents),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    install_local.main()

            self.assertEqual((installed_root / "scripts" / "marker.txt").read_text(encoding="utf-8"), "old-plugin\n")
            self.assertEqual(agents_path.read_text(encoding="utf-8"), "# Existing workspace policy\n")
            self.assertEqual(config_path.read_text(encoding="utf-8"), "[features]\ncodex_hooks = false\n")
            self.assertEqual(json.loads(hooks_path.read_text(encoding="utf-8")), {"hooks": {"PostToolUse": []}})
            self.assertEqual(json.loads(marketplace_path.read_text(encoding="utf-8")), {"plugins": [{"name": "existing"}]})

    def test_main_rolls_back_new_files_and_plugin_install_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as home_dir, tempfile.TemporaryDirectory() as workspace_dir:
            fake_home = Path(home_dir)
            workspace = Path(workspace_dir)
            installed_root = fake_home / ".codex" / "plugins" / "pounce"
            marketplace_path = fake_home / ".agents" / "plugins" / "marketplace.json"

            original_write_file = install_local.InstallTransaction.write_file

            def interrupt_after_marketplace(self: install_local.InstallTransaction, path: Path, content: str) -> bool:
                changed = original_write_file(self, path, content)
                if path == marketplace_path:
                    raise KeyboardInterrupt()
                return changed

            argv = ["install_local.py", "--workspace", str(workspace)]
            with (
                mock.patch.object(Path, "home", return_value=fake_home),
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(install_local.InstallTransaction, "write_file", new=interrupt_after_marketplace),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    install_local.main()

            self.assertFalse(installed_root.exists())
            self.assertFalse(marketplace_path.exists())
            self.assertFalse((workspace / "AGENTS.md").exists())
            self.assertFalse((workspace / ".codex" / "hooks.json").exists())
            self.assertFalse((workspace / ".codex" / "config.toml").exists())


if __name__ == "__main__":
    unittest.main()
