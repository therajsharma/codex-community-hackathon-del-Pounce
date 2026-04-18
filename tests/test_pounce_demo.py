import json
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "plugins" / "pounce" / "scripts" / "pounce_demo.py"


class PounceDemoSmokeTests(unittest.TestCase):
    def test_demo_smoke_passes(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "pass")
        self.assertTrue(all(check["status"] == "pass" for check in payload["checks"]))


if __name__ == "__main__":
    unittest.main()
