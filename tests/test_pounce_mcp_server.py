import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER_SCRIPT = REPO_ROOT / "plugins" / "pounce" / "scripts" / "pounce_mcp_server.py"


class PounceMcpServerTests(unittest.TestCase):
    def _run_server(self, *requests: dict[str, object], cwd: Path | None = None, env: dict[str, str] | None = None) -> list[dict[str, object]]:
        message_stream = "\n".join(json.dumps(request, separators=(",", ":")) for request in requests) + "\n"
        completed = subprocess.run(
            [sys.executable, str(SERVER_SCRIPT)],
            input=message_stream.encode("utf-8"),
            capture_output=True,
            check=False,
            cwd=str(cwd) if cwd else None,
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
        return [json.loads(line) for line in completed.stdout.decode("utf-8").splitlines() if line.strip()]

    def test_initialize_uses_newline_delimited_json_rpc(self) -> None:
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            },
        }

        completed = subprocess.run(
            [sys.executable, str(SERVER_SCRIPT)],
            input=(json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8"),
            capture_output=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
        self.assertFalse(completed.stderr)

        response_lines = completed.stdout.decode("utf-8").splitlines()
        self.assertEqual(len(response_lines), 1)
        self.assertNotIn("Content-Length:", response_lines[0])

        response = json.loads(response_lines[0])
        self.assertEqual(response["jsonrpc"], "2.0")
        self.assertEqual(response["id"], 1)
        self.assertEqual(response["result"]["protocolVersion"], "2025-03-26")
        self.assertEqual(response["result"]["serverInfo"]["name"], "pounce")

    def test_tools_list_includes_vet_and_dashboard(self) -> None:
        responses = self._run_server(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-03-26"},
            },
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        )

        tools_list = next(item for item in responses if item["id"] == 2)
        tool_names = [tool["name"] for tool in tools_list["result"]["tools"]]
        self.assertIn("pounce.vet", tool_names)
        self.assertIn("pounce.dashboard", tool_names)

    def test_dashboard_call_returns_markdown_and_structured_content(self) -> None:
        with tempfile.TemporaryDirectory() as workspace_dir, tempfile.TemporaryDirectory() as state_dir:
            workspace = Path(workspace_dir)
            (workspace / "AGENTS.md").write_text("<!-- BEGIN POUNCE MANAGED BLOCK -->\n<!-- END POUNCE MANAGED BLOCK -->\n", encoding="utf-8")
            (workspace / "package.json").write_text(json.dumps({"dependencies": {"demo": "1.0.0"}}), encoding="utf-8")
            env = {**os.environ, "POUNCE_STATE_DIR": state_dir}
            responses = self._run_server(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-03-26"},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "pounce.dashboard",
                        "arguments": {"workspace": str(workspace)},
                    },
                },
                cwd=workspace,
                env=env,
            )

        tool_call = next(item for item in responses if item["id"] == 2)
        content_text = tool_call["result"]["content"][0]["text"]
        structured = tool_call["result"]["structuredContent"]
        self.assertIn("## Pounce Dashboard", content_text)
        self.assertIn("### Workspace", content_text)
        self.assertIn("### Feed", content_text)
        self.assertIn("### Recent Verdicts", content_text)
        self.assertIn("generated_at", structured)
        self.assertIn("workspace", structured)
        self.assertIn("feed", structured)
        self.assertIn("recent_verdicts", structured)


if __name__ == "__main__":
    unittest.main()
