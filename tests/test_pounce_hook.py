import json
import subprocess
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

import pounce_hook  # noqa: E402


class PounceHookTests(unittest.TestCase):
    def test_user_prompt_submit_creates_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "package.json").write_text(
                json.dumps({"dependencies": {"demo": "1.0.0"}}),
                encoding="utf-8",
            )
            result = pounce_hook.process_payload(
                {
                    "hook_event_name": "UserPromptSubmit",
                    "cwd": str(workspace),
                    "session_id": "session-1",
                    "prompt": "add demo",
                },
                script_file=str(SCRIPTS_ROOT / "pounce_hook.py"),
            )
            state_path = workspace / ".pounce" / "guard" / "turn-session-1.json"
            self.assertIsNone(result)
            self.assertTrue(state_path.exists())

    def test_pre_tool_use_records_allowlist_for_vetted_install(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "package.json").write_text(json.dumps({"dependencies": {}}), encoding="utf-8")
            pounce_hook.process_payload(
                {
                    "hook_event_name": "UserPromptSubmit",
                    "cwd": str(workspace),
                    "session_id": "session-2",
                    "prompt": "install demo",
                },
                script_file=str(SCRIPTS_ROOT / "pounce_hook.py"),
            )
            with mock.patch(
                "pounce_hook.assess_dependency_command",
                return_value={
                    "matched": True,
                    "block": False,
                    "message": None,
                    "expected_mutations": [
                        {
                            "ecosystem": "npm",
                            "manager": "npm",
                            "verb": "install",
                            "name": "demo",
                            "expected_version": "1.2.0",
                            "command": "npm install demo@1.2.0 --save-exact",
                        }
                    ],
                },
            ):
                result = pounce_hook.process_payload(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "Bash",
                        "tool_input": {"command": "npm install demo@1.2.0 --save-exact"},
                        "cwd": str(workspace),
                        "session_id": "session-2",
                    },
                    script_file=str(SCRIPTS_ROOT / "pounce_hook.py"),
                )
            state_path = workspace / ".pounce" / "guard" / "turn-session-2.json"
            payload = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertIsNone(result)
            self.assertEqual(len(payload["allowlist"]), 1)

    def test_stop_blocks_on_unvetted_dependency_edit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "package.json").write_text(
                json.dumps({"dependencies": {"demo": "1.0.0"}}),
                encoding="utf-8",
            )
            pounce_hook.process_payload(
                {
                    "hook_event_name": "UserPromptSubmit",
                    "cwd": str(workspace),
                    "session_id": "session-3",
                    "prompt": "edit package json",
                },
                script_file=str(SCRIPTS_ROOT / "pounce_hook.py"),
            )
            (workspace / "package.json").write_text(
                json.dumps({"dependencies": {"demo": "1.0.0", "leftpad": "^1.3.0"}}),
                encoding="utf-8",
            )
            result = pounce_hook.process_payload(
                {
                    "hook_event_name": "Stop",
                    "cwd": str(workspace),
                    "session_id": "session-3",
                },
                script_file=str(SCRIPTS_ROOT / "pounce_hook.py"),
            )
            self.assertIsNotNone(result)
            self.assertEqual(result["decision"], "block")
            self.assertIn("leftpad", result["reason"])

    def test_pre_tool_use_blocks_malformed_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = pounce_hook.process_payload(
                {
                    "hook_event_name": "PreToolUse",
                    "cwd": str(tmpdir),
                    "tool_name": "Bash",
                    "tool_input": {},
                },
                script_file=str(SCRIPTS_ROOT / "pounce_hook.py"),
            )
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_stop_blocks_on_corrupt_guard_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "package.json").write_text(json.dumps({"dependencies": {"demo": "1.0.0"}}), encoding="utf-8")
            guard_dir = workspace / ".pounce" / "guard"
            guard_dir.mkdir(parents=True, exist_ok=True)
            (guard_dir / "turn-session-4.json").write_text(json.dumps({"snapshot": "invalid"}), encoding="utf-8")
            result = pounce_hook.process_payload(
                {
                    "hook_event_name": "Stop",
                    "cwd": str(workspace),
                    "session_id": "session-4",
                },
                script_file=str(SCRIPTS_ROOT / "pounce_hook.py"),
            )
        self.assertEqual(result["decision"], "block")
        self.assertIn("corrupt", result["reason"])

    def test_pre_tool_use_denies_when_verification_is_degraded(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            with mock.patch(
                "pounce_hook.assess_dependency_command",
                return_value={
                    "matched": True,
                    "block": True,
                    "message": "Pounce could not fully verify `demo@1.2.3`. Manual review is required before installs continue.",
                    "expected_mutations": [],
                },
            ):
                result = pounce_hook.process_payload(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "Bash",
                        "tool_input": {"command": "npm install demo@1.2.3"},
                        "cwd": str(workspace),
                        "session_id": "session-5",
                    },
                    script_file=str(SCRIPTS_ROOT / "pounce_hook.py"),
                )
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_main_fails_closed_on_malformed_json(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPTS_ROOT / "pounce_hook.py")],
            input=b"{",
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("malformed JSON", completed.stderr.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    unittest.main()
