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
    validate_workspace_path_for_write,
)

HOOK_MALFORMED_INPUT_MESSAGE = "Pounce blocked execution because the hook payload was malformed."


def payload_turn_id(payload: dict[str, object]) -> str:
    for key in ("turn_id", "request_id", "message_id", "session_id"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "active"


def block_hook_payload(reason: str, *, hook_event_name: str | None) -> dict[str, object]:
    if hook_event_name == "PreToolUse":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    return {"decision": "block", "reason": reason}


def process_payload(payload: dict[str, object], script_file: str = __file__) -> dict[str, object] | None:
    hook_event_name_value = payload.get("hook_event_name")
    hook_event_name = hook_event_name_value.strip() if isinstance(hook_event_name_value, str) else None
    plugin_root = plugin_root_from_script(script_file)
    if hook_event_name not in {"UserPromptSubmit", "PreToolUse", "Stop"}:
        return block_hook_payload(HOOK_MALFORMED_INPUT_MESSAGE, hook_event_name=hook_event_name)

    cwd_value = payload.get("cwd")
    if not isinstance(cwd_value, str) or not cwd_value.strip():
        return block_hook_payload(HOOK_MALFORMED_INPUT_MESSAGE, hook_event_name=hook_event_name)
    try:
        workspace = validate_workspace_path_for_write(
            Path(cwd_value),
            plugin_root=plugin_root,
            allowed_root=Path(cwd_value).expanduser().resolve(),
        )
    except ValueError:
        return block_hook_payload(HOOK_MALFORMED_INPUT_MESSAGE, hook_event_name=hook_event_name)

    turn_id = payload_turn_id(payload)

    if hook_event_name == "UserPromptSubmit":
        snapshot_dependency_guard(workspace, turn_id, allowed_workspace_root=workspace)
        return None

    if hook_event_name == "PreToolUse":
        tool_name = payload.get("tool_name")
        if tool_name != "Bash":
            if tool_name is None:
                return block_hook_payload(HOOK_MALFORMED_INPUT_MESSAGE, hook_event_name=hook_event_name)
            return None
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, dict):
            return block_hook_payload(HOOK_MALFORMED_INPUT_MESSAGE, hook_event_name=hook_event_name)
        command = str(tool_input.get("command", "")).strip()
        if not command:
            return block_hook_payload(HOOK_MALFORMED_INPUT_MESSAGE, hook_event_name=hook_event_name)
        assessment = assess_dependency_command(command, plugin_root, workspace)
        if not assessment.get("matched"):
            return None
        if not assessment.get("block") and assessment.get("expected_mutations"):
            record_dependency_guard_allowlist(
                workspace,
                turn_id,
                assessment["expected_mutations"],
                allowed_workspace_root=workspace,
            )
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
        assessment = assess_dependency_guard(workspace, turn_id, allowed_workspace_root=workspace)
        if assessment.get("block"):
            return {"decision": "block", "reason": assessment["message"]}
        return None

    return None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.stderr.write("Pounce hook received malformed JSON input.\n")
        return 1
    if not isinstance(payload, dict):
        sys.stderr.write("Pounce hook received malformed JSON input.\n")
        return 1

    result = process_payload(payload)
    if result is not None:
        json.dump(result, sys.stdout)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
