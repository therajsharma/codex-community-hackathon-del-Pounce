#!/usr/bin/env python3
"""Hook entrypoint for Pounce."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pounce_runtime import (
    assess_dependency_command,
    assess_dependency_guard,
    plugin_root_from_script,
    record_dependency_guard_allowlist,
    snapshot_dependency_guard,
)


def payload_turn_id(payload: dict[str, object]) -> str:
    for key in ("turn_id", "request_id", "message_id", "session_id"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "active"


def process_payload(payload: dict[str, object], script_file: str = __file__) -> dict[str, object] | None:
    hook_event_name = payload.get("hook_event_name")
    workspace = Path(payload.get("cwd") or ".").resolve()
    plugin_root = plugin_root_from_script(script_file)
    turn_id = payload_turn_id(payload)

    if hook_event_name == "UserPromptSubmit":
        snapshot_dependency_guard(workspace, turn_id)
        return None

    if hook_event_name == "PreToolUse":
        if payload.get("tool_name") != "Bash":
            return None
        command = str((payload.get("tool_input") or {}).get("command", "")).strip()
        if not command:
            return None
        assessment = assess_dependency_command(command, plugin_root, workspace)
        if not assessment.get("matched"):
            return None
        if not assessment.get("block") and assessment.get("expected_mutations"):
            record_dependency_guard_allowlist(workspace, turn_id, assessment["expected_mutations"])
        if assessment.get("block"):
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": assessment["message"],
                }
            }
        if assessment.get("message"):
            return {"systemMessage": assessment["message"]}
        return None

    if hook_event_name == "Stop":
        assessment = assess_dependency_guard(workspace, turn_id)
        if assessment.get("block"):
            return {"decision": "block", "reason": assessment["message"]}
        return None

    return None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0

    result = process_payload(payload)
    if result is not None:
        json.dump(result, sys.stdout)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
