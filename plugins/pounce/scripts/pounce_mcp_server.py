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
PARSE_ERROR_CODE = -32700
INVALID_REQUEST_CODE = -32600
METHOD_NOT_FOUND_CODE = -32601
INVALID_PARAMS_CODE = -32602


class ValidationError(Exception):
    """Raised when an MCP request payload is invalid."""


def read_raw_line() -> bytes | None:
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        if line in {b"\r\n", b"\n"}:
            continue
        return line


def send_message(payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(encoded + b"\n")
    sys.stdout.buffer.flush()


def send_error(message_id: Any, code: int, message: str) -> None:
    send_message(
        {
            "jsonrpc": "2.0",
            "id": message_id,
            "error": {
                "code": code,
                "message": message,
            },
        }
    )


def tool_error_response(message_id: Any, *, error_code: str, text: str) -> None:
    send_message(
        {
            "jsonrpc": "2.0",
            "id": message_id,
            "result": {
                "isError": True,
                "content": [{"type": "text", "text": text}],
                "structuredContent": {"error_code": error_code},
            },
        }
    )


def parse_message_line(line: bytes) -> dict[str, Any]:
    try:
        decoded = line.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("Parse error.") from exc
    try:
        message = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise ValidationError("Parse error.") from exc
    if not isinstance(message, dict):
        raise ValidationError("Invalid request.")
    return message


def ensure_object(value: Any, *, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValidationError(f"`{field_name}` must be an object.")
    return value


def ensure_string(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"`{field_name}` must be a string.")
    return value


def ensure_optional_string(value: Any, *, field_name: str) -> str | None:
    if value is None:
        return None
    return ensure_string(value, field_name=field_name)


def ensure_string_or_string_list(value: Any, *, field_name: str) -> str | list[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    raise ValidationError(f"`{field_name}` must be a string or an array of strings.")


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


def validate_vet_arguments(arguments: Any) -> dict[str, Any]:
    payload = ensure_object(arguments, field_name="arguments")
    allowed_fields = {"mode", "ecosystem", "package_name", "version", "artifacts", "ioc_query", "workspace", "reason"}
    extra_fields = sorted(set(payload) - allowed_fields)
    if extra_fields:
        raise ValidationError(f"Unknown `pounce.vet` arguments: {', '.join(extra_fields)}.")

    mode = payload.get("mode", "release")
    if mode is not None:
        mode = ensure_string(mode, field_name="mode").strip().lower()
    if mode not in {"release", "sweep"}:
        raise ValidationError("`mode` must be `release` or `sweep`.")

    ecosystem = ensure_optional_string(payload.get("ecosystem"), field_name="ecosystem")
    if ecosystem is not None and ecosystem not in {"npm", "pypi", "mixed"}:
        raise ValidationError("`ecosystem` must be `npm`, `pypi`, or `mixed`.")

    package_name = ensure_optional_string(payload.get("package_name"), field_name="package_name")
    version = ensure_optional_string(payload.get("version"), field_name="version")
    workspace = ensure_optional_string(payload.get("workspace"), field_name="workspace")
    reason = ensure_optional_string(payload.get("reason"), field_name="reason")
    artifacts = ensure_string_or_string_list(payload.get("artifacts"), field_name="artifacts")
    ioc_query = ensure_string_or_string_list(payload.get("ioc_query"), field_name="ioc_query")

    release_fields_present = any(
        field is not None and field.strip()
        for field in (ecosystem, package_name, version)
    )
    if release_fields_present and not all(field is not None and field.strip() for field in (ecosystem, package_name, version)):
        raise ValidationError("Exact release vetting requires `ecosystem`, `package_name`, and `version` together.")
    if mode == "sweep" and not (workspace and workspace.strip()):
        raise ValidationError("Sweep mode requires `workspace`.")

    validated = {"mode": mode}
    for key, value in (
        ("ecosystem", ecosystem),
        ("package_name", package_name),
        ("version", version),
        ("workspace", workspace),
        ("reason", reason),
        ("artifacts", artifacts),
        ("ioc_query", ioc_query),
    ):
        if value is not None:
            validated[key] = value
    return validated


def validate_dashboard_arguments(arguments: Any) -> dict[str, Any]:
    payload = ensure_object(arguments, field_name="arguments")
    extra_fields = sorted(set(payload) - {"workspace"})
    if extra_fields:
        raise ValidationError(f"Unknown `pounce.dashboard` arguments: {', '.join(extra_fields)}.")
    workspace = ensure_optional_string(payload.get("workspace"), field_name="workspace")
    return {"workspace": workspace} if workspace is not None else {}


def handle_request(message: dict[str, Any], plugin_root: Path) -> None:
    method = message.get("method")
    message_id = message.get("id")
    params = ensure_object(message.get("params"), field_name="params")

    if not isinstance(method, str) or not method:
        send_error(message_id, INVALID_REQUEST_CODE, "Invalid request.")
        return

    if method == "initialize":
        protocol_version = params.get("protocolVersion", "2025-03-26")
        if protocol_version is not None and not isinstance(protocol_version, str):
            send_error(message_id, INVALID_PARAMS_CODE, "Invalid params.")
            return
        send_message(
            {
                "jsonrpc": "2.0",
                "id": message_id,
                "result": {
                    "protocolVersion": protocol_version or "2025-03-26",
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
        if not isinstance(name, str) or not name:
            tool_error_response(message_id, error_code="invalid_tool_name", text="Invalid tool name.")
            return

        if name not in {"pounce.vet", "pounce.dashboard"}:
            tool_error_response(message_id, error_code="unknown_tool", text="Unknown tool.")
            return

        try:
            if name == "pounce.dashboard":
                arguments = validate_dashboard_arguments(params.get("arguments"))
                result = build_dashboard_snapshot(arguments, plugin_root, current_workspace=Path.cwd())
                content_text = render_dashboard_markdown(result)
            else:
                arguments = validate_vet_arguments(params.get("arguments"))
                result = vet_payload(arguments, plugin_root, allowed_workspace_root=Path.cwd())
                content_text = json.dumps(result, indent=2)
        except ValidationError:
            tool_error_response(message_id, error_code="invalid_arguments", text="Invalid tool arguments.")
            return
        except Exception:
            tool_error_response(message_id, error_code="internal_error", text="Pounce failed due to an internal error.")
            return

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
        return

    if message_id is not None:
        send_error(message_id, METHOD_NOT_FOUND_CODE, f"Method not found: {method}")


def main() -> int:
    plugin_root = plugin_root_from_script(__file__)
    while True:
        line = read_raw_line()
        if line is None:
            return 0
        try:
            message = parse_message_line(line)
            handle_request(message, plugin_root)
        except ValidationError as exc:
            message_text = str(exc)
            if message_text == "Parse error.":
                send_error(None, PARSE_ERROR_CODE, message_text)
            else:
                send_error(None, INVALID_REQUEST_CODE, message_text)


if __name__ == "__main__":
    raise SystemExit(main())
