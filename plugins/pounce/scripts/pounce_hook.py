#!/usr/bin/env python3
"""Bash hook entrypoint for Pounce."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pounce_runtime import assess_dependency_command, plugin_root_from_script


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0

    if payload.get("hook_event_name") != "PreToolUse":
        return 0
    if payload.get("tool_name") != "Bash":
        return 0

    command = str((payload.get("tool_input") or {}).get("command", "")).strip()
    if not command:
        return 0

    plugin_root = plugin_root_from_script(__file__)
    workspace = Path(payload.get("cwd") or ".").resolve()
    assessment = assess_dependency_command(command, plugin_root, workspace)
    if not assessment.get("matched"):
        return 0

    if assessment.get("block"):
        json.dump(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": assessment["message"],
                }
            },
            sys.stdout,
        )
        sys.stdout.write("\n")
        return 0

    if assessment.get("message"):
        json.dump({"systemMessage": assessment["message"]}, sys.stdout)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
