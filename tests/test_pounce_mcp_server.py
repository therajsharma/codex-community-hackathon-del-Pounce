import json
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER_SCRIPT = REPO_ROOT / "plugins" / "pounce" / "scripts" / "pounce_mcp_server.py"


class PounceMcpServerTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
