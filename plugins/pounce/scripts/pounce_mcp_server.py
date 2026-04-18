#!/usr/bin/env python3
"""Minimal stdio MCP server for the Pounce plugin."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from pounce_runtime import build_dashboard_snapshot, plugin_root_from_script, render_dashboard_markdown, vet_payload


SERVER_NAME = "pounce"
SERVER_VERSION = "0.1.0"


def read_message() -> dict[str, Any] | None:
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        if line in {b"\r\n", b"\n"}:
            continue
        return json.loads(line.decode("utf-8"))


def send_message(payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(encoded + b"\n")
    sys.stdout.buffer.flush()


def vet_tool_schema() -> dict[str, Any]:
    return {
        "name": "pounce.vet",
        "description": "Vet dependency releases, suspicious artifact strings, or a workspace sweep for supply-chain risk signals.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["release", "sweep"],
                    "description": "Use `release` for exact package/version vetting or `sweep` for workspace scans.",
                },
                "ecosystem": {
                    "type": "string",
                    "enum": ["npm", "pypi", "mixed"],
                    "description": "Package ecosystem for release vetting.",
                },
                "package_name": {"type": "string"},
                "version": {"type": "string"},
                "artifacts": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}},
                    ]
                },
                "ioc_query": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}},
                    ]
                },
                "workspace": {"type": "string"},
                "reason": {"type": "string"},
            },
            "additionalProperties": False,
        },
    }


def dashboard_tool_schema() -> dict[str, Any]:
    return {
        "name": "pounce.dashboard",
        "description": "Show a structured Pounce dashboard snapshot for the current workspace, feed status, and recent verdicts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace": {
                    "type": "string",
                    "description": "Optional workspace root to inspect. When omitted, Pounce will use a best-effort current-workspace fallback.",
                }
            },
            "additionalProperties": False,
        },
    }


def handle_request(message: dict[str, Any], plugin_root: Path) -> None:
    method = message.get("method")
    message_id = message.get("id")
    params = message.get("params", {})

    if method == "initialize":
        send_message(
            {
                "jsonrpc": "2.0",
                "id": message_id,
                "result": {
                    "protocolVersion": params.get("protocolVersion", "2025-03-26"),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                },
            }
        )
        return

    if method in {"notifications/initialized", "initialized"}:
        return

    if method == "ping":
        send_message({"jsonrpc": "2.0", "id": message_id, "result": {}})
        return

    if method == "tools/list":
        send_message(
            {
                "jsonrpc": "2.0",
                "id": message_id,
                "result": {"tools": [vet_tool_schema(), dashboard_tool_schema()]},
            }
        )
        return

    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments", {})
        if name not in {"pounce.vet", "pounce.dashboard"}:
            send_message(
                {
                    "jsonrpc": "2.0",
                    "id": message_id,
                    "result": {
                        "isError": True,
                        "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
                    },
                }
            )
            return
        try:
            if name == "pounce.dashboard":
                result = build_dashboard_snapshot(arguments, plugin_root, current_workspace=Path.cwd())
                content_text = render_dashboard_markdown(result)
            else:
                result = vet_payload(arguments, plugin_root)
                content_text = json.dumps(result, indent=2)
            send_message(
                {
                    "jsonrpc": "2.0",
                    "id": message_id,
                    "result": {
                        "content": [{"type": "text", "text": content_text}],
                        "structuredContent": result,
                    },
                }
            )
        except Exception as exc:  # pragma: no cover - defensive server path
            send_message(
                {
                    "jsonrpc": "2.0",
                    "id": message_id,
                    "result": {
                        "isError": True,
                        "content": [{"type": "text", "text": f"Pounce failed: {exc}"}],
                    },
                }
            )
        return

    if message_id is not None:
        send_message(
            {
                "jsonrpc": "2.0",
                "id": message_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        )


def main() -> int:
    plugin_root = plugin_root_from_script(__file__)
    while True:
        message = read_message()
        if message is None:
            return 0
        handle_request(message, plugin_root)


if __name__ == "__main__":
    raise SystemExit(main())
