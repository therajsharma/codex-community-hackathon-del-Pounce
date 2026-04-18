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


if __name__ == "__main__":
    unittest.main()
