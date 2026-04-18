#!/usr/bin/env python3
"""Threat intelligence feed support for Pounce."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urlparse
from urllib.request import Request, urlopen


FEED_SCHEMA_VERSION = "1.0"
DEFAULT_STATE_DIR = Path.home() / ".codex" / "pounce"
DEFAULT_FEED_STALE_AFTER_HOURS = 6
HTTP_USER_AGENT = "pounce-local-plugin"
GITHUB_API_ROOT = "https://api.github.com"
OSV_API_ROOT = "https://api.osv.dev"
OSV_EXPORT_ROOT = "https://storage.googleapis.com/osv-vulnerabilities"
KNOWN_REFERENCE_HOSTS = {
    "api.github.com",
    "github.com",
    "osv.dev",
    "api.osv.dev",
    "storage.googleapis.com",
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "npmjs.com",
}
URL_RE = re.compile(r"https?://[^\s<>'\"`]+", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"(?<![@/A-Za-z0-9-])((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?::\d{2,5})?(?:/|(?=\s|$|[)\],;]))",
    re.IGNORECASE,
)
IP_RE = re.compile(r"(?<!\d)((?:\d{1,3}\.){3}\d{1,3})(?!\d)")
VERSION_TOKEN_RE = re.compile(r"[A-Za-z]+|\d+")
NPM_EXACT_VERSION_RE = re.compile(r"^v?\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
PYTHON_EXACT_SPEC_RE = re.compile(r"^(?:===|==)\s*[^,*;\s]+$")


class IntelUnavailable(Exception):
    """Raised when an intelligence source could not be queried."""


@dataclass(slots=True)
class HttpResponse:
    text: str
    headers: dict[str, str]


def now_utc() -> datetime:
    return datetime.now(tz=UTC)


def iso_now() -> str:
    return now_utc().isoformat().replace("+00:00", "Z")


def parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def clamp_confidence(value: Any, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, parsed))


def normalize_ecosystem(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"npm", "node", "javascript"}:
        return "npm"
    if normalized in {"pypi", "python", "pip"}:
        return "pypi"
    return normalized


def state_dir() -> Path:
    configured = str(os.getenv("POUNCE_STATE_DIR", "")).strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return DEFAULT_STATE_DIR


def feed_cache_path() -> Path:
    return state_dir() / "feed.json"


def sync_state_path() -> Path:
    return state_dir() / "state.json"


def load_json_file(path: Path, *, default: Any = None) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def stale_after_hours() -> int:
    raw = str(os.getenv("POUNCE_FEED_STALE_AFTER_HOURS", DEFAULT_FEED_STALE_AFTER_HOURS)).strip()
    try:
        parsed = int(raw)
    except ValueError:
        return DEFAULT_FEED_STALE_AFTER_HOURS
    return max(1, parsed)


def vulnerability_action() -> str:
    action = str(os.getenv("POUNCE_VULNERABILITY_ACTION", "warn")).strip().lower()
    return action if action in {"warn", "block"} else "warn"


def github_token() -> str | None:
    for name in ("POUNCE_GITHUB_TOKEN", "GITHUB_TOKEN"):
        value = str(os.getenv(name, "")).strip()
        if value:
            return value
    return None


def request_text(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    method: str | None = None,
    timeout: int = 20,
) -> HttpResponse:
    request = Request(
        url,
        data=data,
        method=method,
        headers={
            "Accept": "application/json",
            "User-Agent": HTTP_USER_AGENT,
            **(headers or {}),
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            text = response.read().decode("utf-8")
            response_headers = {key: value for key, value in response.headers.items()}
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace") if exc.fp is not None else ""
        raise IntelUnavailable(f"{url} returned HTTP {exc.code}: {detail or exc.reason}") from exc
    except URLError as exc:
        raise IntelUnavailable(f"{url} could not be reached: {exc.reason}") from exc
    return HttpResponse(text=text, headers=response_headers)


def request_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    payload: Any = None,
    method: str | None = None,
    timeout: int = 20,
) -> tuple[Any, dict[str, str]]:
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json", **(headers or {})}
    response = request_text(url, headers=headers, data=data, method=method, timeout=timeout)
    try:
        parsed = json.loads(response.text)
    except json.JSONDecodeError as exc:
        raise IntelUnavailable(f"{url} returned invalid JSON.") from exc
    return parsed, response.headers


def feed_cache_envelope(feed: dict[str, Any], *, fetched_at: str, fetched_from: str | None) -> dict[str, Any]:
    return {
        "feed": feed,
        "fetched_at": fetched_at,
        "fetched_from": fetched_from,
    }


def load_cached_feed_envelope() -> dict[str, Any] | None:
    payload = load_json_file(feed_cache_path(), default=None)
    return payload if isinstance(payload, dict) else None


def persist_feed_cache(feed: dict[str, Any], *, fetched_at: str | None = None, fetched_from: str | None = None) -> None:
    write_json(
        feed_cache_path(),
        feed_cache_envelope(feed, fetched_at=fetched_at or iso_now(), fetched_from=fetched_from),
    )


def default_source_refs(source: str, item_id: str, refs: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in refs or []:
        if not isinstance(item, dict):
            continue
        entry = {key: value for key, value in item.items() if value not in {None, ""}}
        if entry:
            normalized.append(entry)
    if normalized:
        return normalized
    return [{"kind": source, "id": item_id}]


def normalize_reason(value: Any, *, fallback: str) -> str:
    text = str(value or "").strip()
    return text or fallback


def normalize_match_payload(match: Any) -> dict[str, Any] | None:
    if not isinstance(match, dict):
        return None
    raw_type = str(match.get("type", "")).strip().lower()
    if raw_type == "package":
        ecosystem = normalize_ecosystem(match.get("ecosystem"))
        name = str(match.get("name", "")).strip()
        version = str(match.get("version", "")).strip()
        if ecosystem and name and version:
            return {
                "type": "package_exact",
                "ecosystem": ecosystem,
                "name": name,
                "version": version,
            }
        return None
    if raw_type in {"package_exact", "package_range"}:
        ecosystem = normalize_ecosystem(match.get("ecosystem"))
        name = str(match.get("name", "")).strip()
        if not ecosystem or not name:
            return None
        normalized = {"type": raw_type, "ecosystem": ecosystem, "name": name}
        if raw_type == "package_exact":
            version = str(match.get("version", "")).strip()
            if not version:
                return None
            normalized["version"] = version
        else:
            version_spec = str(match.get("version_spec", "") or match.get("versionRange", "")).strip()
            if not version_spec:
                return None
            normalized["version_spec"] = version_spec
        return normalized
    if raw_type in {"string", "domain", "ip", "url"}:
        value = str(match.get("value", "")).strip()
        if not value:
            return None
        return {"type": raw_type, "value": value}
    return None


def normalize_legacy_item(item: dict[str, Any], *, observed_at: str, source: str) -> dict[str, Any] | None:
    match = normalize_match_payload(item.get("match"))
    if match is None:
        return None
    severity = str(item.get("severity", "")).strip().lower()
    action = "block" if severity in {"critical", "high"} else "warn"
    item_id = str(item.get("id", "")).strip() or f"{source}-{match['type']}-{hash(json.dumps(match, sort_keys=True))}"
    return {
        "id": item_id,
        "kind": "malicious_package" if match["type"].startswith("package") else "ioc_string",
        "match": match,
        "action": action,
        "confidence": 1.0 if action == "block" else 0.75,
        "reason": normalize_reason(item.get("reason"), fallback="Legacy seeded IOC."),
        "source": source,
        "source_refs": default_source_refs(source, item_id),
        "published_at": observed_at,
        "modified_at": observed_at,
        "first_seen": observed_at,
        "last_seen": observed_at,
        "metadata": {"legacy": True},
    }


def normalize_feed_item(item: dict[str, Any], *, observed_at: str, default_source: str | None = None) -> dict[str, Any] | None:
    if "match" in item and "action" in item:
        match = normalize_match_payload(item.get("match"))
        if match is None:
            return None
        item_id = str(item.get("id", "")).strip()
        if not item_id:
            return None
        action = str(item.get("action", "warn")).strip().lower()
        if action not in {"warn", "block"}:
            action = "warn"
        source = str(item.get("source", "")).strip() or str(default_source or "feed").strip()
        published_at = str(item.get("published_at", "")).strip() or observed_at
        modified_at = str(item.get("modified_at", "")).strip() or published_at
        first_seen = str(item.get("first_seen", "")).strip() or observed_at
        last_seen = str(item.get("last_seen", "")).strip() or modified_at
        normalized: dict[str, Any] = {
            "id": item_id,
            "kind": str(item.get("kind", "")).strip() or ("malicious_package" if action == "block" else "vulnerability"),
            "match": match,
            "action": action,
            "confidence": clamp_confidence(item.get("confidence"), 0.5 if action == "warn" else 1.0),
            "reason": normalize_reason(item.get("reason"), fallback="Threat intelligence finding."),
            "source": source or "feed",
            "source_refs": default_source_refs(source or "feed", item_id, item.get("source_refs")),
            "published_at": published_at,
            "modified_at": modified_at,
            "first_seen": first_seen,
            "last_seen": last_seen,
        }
        for optional in ("expires_at", "revoked_at", "revocation_reason", "signature"):
            value = item.get(optional)
            if value not in {None, ""}:
                normalized[optional] = value
        metadata = item.get("metadata")
        if isinstance(metadata, dict) and metadata:
            normalized["metadata"] = metadata
        return normalized
    return normalize_legacy_item(item, observed_at=observed_at, source=default_source or "seed_ioc")


def normalize_feed_artifact(payload: Any, *, observed_at: str | None = None, default_source: str | None = None) -> dict[str, Any]:
    observed = observed_at or iso_now()
    if isinstance(payload, list):
        raw_items = payload
        sources: list[dict[str, Any]] = []
        schema_version = FEED_SCHEMA_VERSION
        generated_at = observed
        signature = None
    elif isinstance(payload, dict):
        raw_items = payload.get("items", [])
        sources = payload.get("sources", [])
        schema_version = str(payload.get("schema_version", FEED_SCHEMA_VERSION)).strip() or FEED_SCHEMA_VERSION
        generated_at = str(payload.get("generated_at", "")).strip() or observed
        signature = payload.get("signature")
    else:
        raise ValueError("Feed payload must be a JSON object or array.")
    if not isinstance(raw_items, list):
        raise ValueError("Feed items must be a list.")
    items: list[dict[str, Any]] = []
    for raw_item in raw_items:
        if not isinstance(raw_item, dict):
            continue
        normalized = normalize_feed_item(raw_item, observed_at=observed, default_source=default_source)
        if normalized is not None:
            items.append(normalized)
    artifact: dict[str, Any] = {
        "schema_version": schema_version,
        "generated_at": generated_at,
        "sources": sources if isinstance(sources, list) else [],
        "items": sorted(items, key=lambda item: item["id"]),
    }
    if signature is not None:
        artifact["signature"] = signature
    return artifact


def merge_feed_artifacts(*artifacts: dict[str, Any] | None) -> dict[str, Any]:
    merged_items: dict[str, dict[str, Any]] = {}
    sources: list[dict[str, Any]] = []
    generated_at = iso_now()
    signature: Any = None
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        generated_at = str(artifact.get("generated_at", generated_at)).strip() or generated_at
        if isinstance(artifact.get("sources"), list):
            sources.extend(item for item in artifact["sources"] if isinstance(item, dict))
        for item in artifact.get("items", []) or []:
            if isinstance(item, dict) and item.get("id"):
                merged_items[str(item["id"])] = item
        if "signature" in artifact:
            signature = artifact.get("signature")
    payload: dict[str, Any] = {
        "schema_version": FEED_SCHEMA_VERSION,
        "generated_at": generated_at,
        "sources": sources,
        "items": sorted(merged_items.values(), key=lambda item: item["id"]),
    }
    if signature is not None:
        payload["signature"] = signature
    return payload


def load_feed_from_text(text: str, *, default_source: str | None = None) -> dict[str, Any]:
    stripped = text.strip()
    if not stripped:
        return normalize_feed_artifact({"items": []}, default_source=default_source)
    if stripped.startswith("{") or stripped.startswith("["):
        payload = json.loads(stripped)
        return normalize_feed_artifact(payload, default_source=default_source)
    items: list[dict[str, Any]] = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        parsed = json.loads(line)
        if isinstance(parsed, dict):
            items.append(parsed)
    return normalize_feed_artifact(items, default_source=default_source)


def item_is_active(item: dict[str, Any], *, at: datetime | None = None) -> bool:
    current = at or now_utc()
    revoked_at = parse_timestamp(item.get("revoked_at"))
    if revoked_at is not None and revoked_at <= current:
        return False
    expires_at = parse_timestamp(item.get("expires_at"))
    if expires_at is not None and expires_at <= current:
        return False
    return True


def active_feed_items(items: list[dict[str, Any]], *, at: datetime | None = None) -> list[dict[str, Any]]:
    return [item for item in items if item_is_active(item, at=at)]


def indicator_metadata(item: dict[str, Any]) -> dict[str, Any]:
    metadata = dict(item.get("metadata") or {})
    metadata.update(
        {
            "intel_id": item.get("id"),
            "intel_kind": item.get("kind"),
            "confidence": item.get("confidence"),
            "source_refs": item.get("source_refs"),
            "published_at": item.get("published_at"),
            "modified_at": item.get("modified_at"),
            "first_seen": item.get("first_seen"),
            "last_seen": item.get("last_seen"),
            "revoked_at": item.get("revoked_at"),
            "expires_at": item.get("expires_at"),
        }
    )
    filtered: dict[str, Any] = {}
    for key, value in metadata.items():
        if value is None:
            continue
        if value == "":
            continue
        if isinstance(value, (list, dict)) and not value:
            continue
        filtered[key] = value
    return filtered


def version_sort_key(version: str) -> tuple[Any, ...]:
    match = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$", version.strip())
    if not match:
        return (0, version)
    prerelease = match.group(4) or ""
    prerelease_key = tuple(str(part) for part in prerelease.split(".") if part)
    return (
        1,
        int(match.group(1)),
        int(match.group(2) or 0),
        int(match.group(3) or 0),
        1 if not prerelease else 0,
        prerelease_key,
    )


def compare_versions(left: str, right: str) -> int:
    left_key = version_sort_key(left)
    right_key = version_sort_key(right)
    if left_key == right_key:
        return 0
    return 1 if left_key > right_key else -1


def normalize_comparison_version(value: str) -> tuple[int, int, int]:
    candidate = value.strip().lstrip("v")
    parts = [part for part in re.split(r"[.-]", candidate) if part]
    numbers = [int(part) for part in parts[:3] if part.isdigit()]
    while len(numbers) < 3:
        numbers.append(0)
    return tuple(numbers[:3])  # type: ignore[return-value]


def format_version_tuple(value: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in value)


def increment_version(value: tuple[int, int, int], part: str) -> tuple[int, int, int]:
    major, minor, patch = value
    if part == "major":
        return (major + 1, 0, 0)
    if part == "minor":
        return (major, minor + 1, 0)
    return (major, minor, patch + 1)


def npm_version_satisfies(version: str, spec: str | None) -> bool:
    if not spec or spec.strip() in {"", "*"}:
        return True
    candidate = version.strip()
    requested = spec.strip()
    if "||" in requested:
        return any(npm_version_satisfies(candidate, part.strip()) for part in requested.split("||"))
    if requested.startswith("^"):
        lower = normalize_comparison_version(requested[1:])
        if compare_versions(candidate, format_version_tuple(lower)) < 0:
            return False
        upper = increment_version(lower, "major" if lower[0] > 0 else "minor" if lower[1] > 0 else "patch")
        return compare_versions(candidate, format_version_tuple(upper)) < 0
    if requested.startswith("~"):
        lower = normalize_comparison_version(requested[1:])
        if compare_versions(candidate, format_version_tuple(lower)) < 0:
            return False
        parts = requested[1:].split(".")
        upper = increment_version(lower, "major" if len(parts) <= 1 else "minor")
        return compare_versions(candidate, format_version_tuple(upper)) < 0
    if re.fullmatch(r"v?\d+(?:\.\d+)?(?:\.(?:\d+|[xX*]))?(?:[xX*])?", requested) or any(
        marker in requested for marker in ("x", "X", "*")
    ):
        wildcard = requested.replace("*", "x").replace("X", "x").lstrip("v")
        parts = wildcard.split(".")
        major = int(parts[0]) if parts[0] and parts[0] != "x" else 0
        if len(parts) == 1 or parts[1] == "x":
            lower = (major, 0, 0)
            upper = (major + 1, 0, 0)
        elif len(parts) == 2 or parts[2] == "x":
            lower = (major, int(parts[1]), 0)
            upper = (major, int(parts[1]) + 1, 0)
        else:
            lower = (major, int(parts[1]), int(parts[2]))
            upper = increment_version(lower, "patch")
        return compare_versions(candidate, format_version_tuple(lower)) >= 0 and compare_versions(
            candidate, format_version_tuple(upper)
        ) < 0
    if any(requested.startswith(prefix) for prefix in (">=", "<=", ">", "<", "=")) or " " in requested:
        clauses = [clause for clause in requested.split() if clause]
        for clause in clauses:
            operator = next((item for item in (">=", "<=", ">", "<", "=") if clause.startswith(item)), None)
            if operator is None:
                continue
            boundary = clause[len(operator) :].strip()
            comparison = compare_versions(candidate, boundary)
            if operator == ">=" and comparison < 0:
                return False
            if operator == "<=" and comparison > 0:
                return False
            if operator == ">" and comparison <= 0:
                return False
            if operator == "<" and comparison >= 0:
                return False
            if operator == "=" and comparison != 0:
                return False
        return True
    return candidate == requested.lstrip("v")


def python_version_satisfies(version: str, spec: str | None) -> bool:
    if not spec or spec.strip() in {"", "*"}:
        return True
    candidate = version.strip()
    clauses = [clause.strip() for clause in spec.split(",") if clause.strip()]
    for clause in clauses:
        operator = next((item for item in ("===", "==", ">=", "<=", "~=", "!=", ">", "<") if clause.startswith(item)), None)
        if operator is None:
            return False
        boundary = clause[len(operator) :].strip()
        comparison = compare_versions(candidate, boundary)
        if operator in {"===", "=="} and comparison != 0:
            return False
        if operator == "!=" and comparison == 0:
            return False
        if operator == ">=" and comparison < 0:
            return False
        if operator == "<=" and comparison > 0:
            return False
        if operator == ">" and comparison <= 0:
            return False
        if operator == "<" and comparison >= 0:
            return False
        if operator == "~=":
            lower = normalize_comparison_version(boundary)
            if comparison < 0:
                return False
            upper = (lower[0], lower[1] + 1, 0) if len(boundary.split(".")) >= 3 else (lower[0] + 1, 0, 0)
            if compare_versions(candidate, format_version_tuple(upper)) >= 0:
                return False
    return True


def package_item_matches(item: dict[str, Any], *, ecosystem: str, package_name: str, version: str) -> bool:
    match = item.get("match") or {}
    if not isinstance(match, dict):
        return False
    if normalize_ecosystem(match.get("ecosystem")) != normalize_ecosystem(ecosystem):
        return False
    if str(match.get("name", "")).strip().lower() != package_name.strip().lower():
        return False
    match_type = str(match.get("type", "")).strip()
    if match_type == "package_exact":
        return str(match.get("version", "")).strip() == version.strip()
    if match_type == "package_range":
        spec = str(match.get("version_spec", "")).strip()
        if not spec:
            return False
        if normalize_ecosystem(ecosystem) == "npm":
            return npm_version_satisfies(version, spec)
        if normalize_ecosystem(ecosystem) == "pypi":
            return python_version_satisfies(version, spec)
    return False


def artifact_item_matches(item: dict[str, Any], artifact: str) -> bool:
    match = item.get("match") or {}
    if not isinstance(match, dict):
        return False
    value = str(match.get("value", "")).strip()
    if not value:
        return False
    lowered = artifact.lower()
    match_type = str(match.get("type", "")).strip()
    if match_type == "string":
        return value.lower() in lowered
    if match_type == "url":
        return value.lower() in lowered
    if match_type == "domain":
        domain_pattern = re.compile(rf"(?<![A-Za-z0-9-]){re.escape(value.lower())}(?=[^A-Za-z0-9-]|$)")
        return bool(domain_pattern.search(lowered))
    if match_type == "ip":
        ip_pattern = re.compile(rf"(?<!\d){re.escape(value)}(?!\d)")
        return bool(ip_pattern.search(artifact))
    return False


def find_package_matches(items: list[dict[str, Any]], *, ecosystem: str, package_name: str, version: str) -> list[dict[str, Any]]:
    return [
        item
        for item in active_feed_items(items)
        if package_item_matches(item, ecosystem=ecosystem, package_name=package_name, version=version)
    ]


def find_artifact_matches(items: list[dict[str, Any]], artifacts: list[str]) -> list[tuple[dict[str, Any], str]]:
    matches: list[tuple[dict[str, Any], str]] = []
    for item in active_feed_items(items):
        for artifact in artifacts:
            if artifact_item_matches(item, artifact):
                matches.append((item, artifact))
                break
    return matches


def parse_indicator_url(raw_url: str) -> dict[str, str] | None:
    candidate = raw_url.rstrip(").,]")
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    host = parsed.netloc.split("@", 1)[-1].split(":", 1)[0].lower()
    if host in KNOWN_REFERENCE_HOSTS:
        return None
    return {"type": "url", "value": candidate, "host": host}


def parse_indicator_domain(raw_domain: str) -> dict[str, str] | None:
    candidate = raw_domain.rstrip(".").lower()
    if not candidate or candidate in KNOWN_REFERENCE_HOSTS:
        return None
    if "/" in candidate or candidate.startswith("http"):
        return None
    return {"type": "domain", "value": candidate}


def parse_indicator_ip(raw_ip: str) -> dict[str, str] | None:
    octets = raw_ip.split(".")
    if len(octets) != 4:
        return None
    try:
        values = [int(octet) for octet in octets]
    except ValueError:
        return None
    if any(value < 0 or value > 255 for value in values):
        return None
    return {"type": "ip", "value": raw_ip}


def extract_actionable_indicators(*texts: str) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    indicators: list[dict[str, str]] = []
    for text in texts:
        if not text:
            continue
        for match in URL_RE.findall(text):
            parsed = parse_indicator_url(match)
            if parsed is None:
                continue
            key = (parsed["type"], parsed["value"])
            if key not in seen:
                seen.add(key)
                indicators.append(parsed)
                domain = parse_indicator_domain(parsed["host"])
                if domain is not None:
                    domain_key = (domain["type"], domain["value"])
                    if domain_key not in seen:
                        seen.add(domain_key)
                        indicators.append(domain)
        for match in DOMAIN_RE.findall(text):
            parsed = parse_indicator_domain(match)
            if parsed is None:
                continue
            key = (parsed["type"], parsed["value"])
            if key not in seen:
                seen.add(key)
                indicators.append(parsed)
        for match in IP_RE.findall(text):
            parsed = parse_indicator_ip(match)
            if parsed is None:
                continue
            key = (parsed["type"], parsed["value"])
            if key not in seen:
                seen.add(key)
                indicators.append(parsed)
    return indicators


def advisory_indicator_metadata(indicators: list[dict[str, str]]) -> list[dict[str, str]]:
    return [{"match_type": item["type"], "value": item["value"]} for item in indicators]


def exact_version_from_range(ecosystem: str, version_range: str) -> str | None:
    raw = version_range.strip()
    if not raw:
        return None
    if ecosystem == "npm":
        candidate = raw.lstrip("= ").strip()
        return candidate if NPM_EXACT_VERSION_RE.fullmatch(candidate) else None
    if ecosystem == "pypi":
        if PYTHON_EXACT_SPEC_RE.fullmatch(raw):
            for prefix in ("===", "=="):
                if raw.startswith(prefix):
                    return raw[len(prefix) :].strip()
        return raw if NPM_EXACT_VERSION_RE.fullmatch(raw) else None
    return None


def base_item_metadata(metadata: dict[str, Any] | None, indicators: list[dict[str, str]]) -> dict[str, Any]:
    payload = dict(metadata or {})
    if indicators:
        payload["indicators"] = advisory_indicator_metadata(indicators)
    return payload


def build_source_refs(*items: dict[str, Any]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for item in items:
        if item:
            normalized = {key: value for key, value in item.items() if value not in {None, ""}}
            if normalized:
                refs.append(normalized)
    return refs


def github_advisory_source_refs(advisory: dict[str, Any]) -> list[dict[str, Any]]:
    ghsa_id = str(advisory.get("ghsa_id", "")).strip()
    refs = build_source_refs(
        {"kind": "ghsa", "id": ghsa_id} if ghsa_id else {},
        {"kind": "url", "url": advisory.get("html_url")},
        {"kind": "api", "url": advisory.get("url")},
    )
    for reference in advisory.get("references") or []:
        if isinstance(reference, str):
            refs.append({"kind": "reference", "url": reference})
    return refs


def osv_advisory_source_refs(advisory: dict[str, Any]) -> list[dict[str, Any]]:
    advisory_id = str(advisory.get("id", "")).strip()
    refs = build_source_refs(
        {"kind": "osv", "id": advisory_id} if advisory_id else {},
        {"kind": "url", "url": f"https://osv.dev/vulnerability/{advisory_id}"} if advisory_id else {},
    )
    for reference in advisory.get("references") or []:
        if not isinstance(reference, dict):
            continue
        refs.append(
            {
                "kind": str(reference.get("type", "reference")).strip().lower() or "reference",
                "url": reference.get("url"),
            }
        )
    return refs


def osv_range_specs(ranges: list[dict[str, Any]]) -> list[str]:
    specs: list[str] = []
    for entry in ranges:
        if not isinstance(entry, dict) or str(entry.get("type", "")).strip().upper() != "ECOSYSTEM":
            continue
        events = entry.get("events") or []
        lower: str | None = None
        for event in events:
            if not isinstance(event, dict):
                continue
            if "introduced" in event:
                introduced = str(event.get("introduced", "")).strip()
                lower = None if introduced in {"", "0"} else introduced
                continue
            if "fixed" in event:
                fixed = str(event.get("fixed", "")).strip()
                clauses = ([f">={lower}"] if lower else []) + ([f"<{fixed}"] if fixed else [])
                if clauses:
                    specs.append(", ".join(clauses))
                lower = None
                continue
            if "last_affected" in event:
                last_affected = str(event.get("last_affected", "")).strip()
                clauses = ([f">={lower}"] if lower else []) + ([f"<={last_affected}"] if last_affected else [])
                if clauses:
                    specs.append(", ".join(clauses))
                lower = None
                continue
        if lower:
            specs.append(f">={lower}")
    return specs


def normalize_github_advisory(advisory: dict[str, Any], *, observed_at: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    modified_at = str(advisory.get("updated_at", "")).strip() or str(advisory.get("published_at", "")).strip() or observed_at
    published_at = str(advisory.get("published_at", "")).strip() or modified_at
    indicators = extract_actionable_indicators(
        str(advisory.get("summary", "") or ""),
        str(advisory.get("description", "") or ""),
        "\n".join(str(value) for value in advisory.get("references") or [] if isinstance(value, str)),
    )
    refs = github_advisory_source_refs(advisory)
    ghsa_id = str(advisory.get("ghsa_id", "")).strip() or f"github-malware-{abs(hash(json.dumps(advisory, sort_keys=True)))}"
    metadata = base_item_metadata(
        {
            "advisory_type": advisory.get("type"),
            "severity": advisory.get("severity"),
            "withdrawn_at": advisory.get("withdrawn_at"),
        },
        indicators,
    )
    for vulnerability in advisory.get("vulnerabilities") or []:
        if not isinstance(vulnerability, dict):
            continue
        package = vulnerability.get("package") or {}
        ecosystem = normalize_ecosystem(package.get("ecosystem"))
        name = str(package.get("name", "")).strip()
        if not ecosystem or not name:
            continue
        version_range = str(vulnerability.get("vulnerable_version_range", "")).strip()
        exact_version = exact_version_from_range(ecosystem, version_range)
        match = (
            {"type": "package_exact", "ecosystem": ecosystem, "name": name, "version": exact_version}
            if exact_version
            else {"type": "package_range", "ecosystem": ecosystem, "name": name, "version_spec": version_range}
            if version_range
            else None
        )
        if match is None:
            continue
        item_id = f"{ghsa_id}:{ecosystem}:{name}:{match['type']}:{match.get('version') or match.get('version_spec')}"
        item: dict[str, Any] = {
            "id": item_id,
            "kind": "malicious_package",
            "match": match,
            "action": "block",
            "confidence": 1.0,
            "reason": normalize_reason(advisory.get("summary"), fallback="GitHub malware advisory."),
            "source": "github_advisory",
            "source_refs": refs,
            "published_at": published_at,
            "modified_at": modified_at,
            "first_seen": observed_at,
            "last_seen": observed_at,
            "metadata": metadata,
        }
        withdrawn_at = str(advisory.get("withdrawn_at", "")).strip()
        if withdrawn_at:
            item["revoked_at"] = withdrawn_at
            item["revocation_reason"] = "GitHub advisory withdrawn."
        items.append(item)
        for index, indicator in enumerate(indicators, start=1):
            indicator_id = f"{item_id}:indicator:{indicator['type']}:{index}"
            items.append(
                {
                    "id": indicator_id,
                    "kind": f"ioc_{indicator['type']}",
                    "match": {"type": indicator["type"], "value": indicator["value"]},
                    "action": "block",
                    "confidence": 0.95,
                    "reason": normalize_reason(advisory.get("summary"), fallback="GitHub malware indicator."),
                    "source": "github_advisory",
                    "source_refs": refs,
                    "published_at": published_at,
                    "modified_at": modified_at,
                    "first_seen": observed_at,
                    "last_seen": observed_at,
                    "metadata": {"parent_id": item_id},
                    **({"revoked_at": withdrawn_at, "revocation_reason": "GitHub advisory withdrawn."} if withdrawn_at else {}),
                }
            )
    return items


def normalize_osv_advisory(advisory: dict[str, Any], *, observed_at: str, action: str | None = None) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    advisory_id = str(advisory.get("id", "")).strip()
    is_malware = advisory_id.startswith("MAL-")
    item_action = "block" if is_malware else action or vulnerability_action()
    kind = "malicious_package" if is_malware else "vulnerability"
    published_at = str(advisory.get("published", "")).strip() or observed_at
    modified_at = str(advisory.get("modified", "")).strip() or published_at
    withdrawn_at = str(advisory.get("withdrawn", "")).strip()
    details = str(advisory.get("details", "") or "")
    summary = str(advisory.get("summary", "") or "").strip()
    refs = osv_advisory_source_refs(advisory)
    indicators = extract_actionable_indicators(details, "\n".join(
        str((item or {}).get("url", "")) for item in advisory.get("references") or [] if isinstance(item, dict)
    ))
    metadata = base_item_metadata(
        {
            "aliases": advisory.get("aliases"),
            "database_specific": advisory.get("database_specific"),
            "ecosystem_specific": advisory.get("ecosystem_specific"),
            "schema_version": advisory.get("schema_version"),
        },
        indicators,
    )
    for affected in advisory.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package") or {}
        ecosystem = normalize_ecosystem(package.get("ecosystem"))
        name = str(package.get("name", "")).strip()
        if not ecosystem or not name:
            continue
        versions = [str(version).strip() for version in affected.get("versions") or [] if str(version).strip()]
        range_specs = osv_range_specs(affected.get("ranges") or [])
        match_payloads: list[dict[str, Any]] = [
            {"type": "package_exact", "ecosystem": ecosystem, "name": name, "version": version}
            for version in versions
        ]
        for spec in range_specs:
            exact_version = exact_version_from_range(ecosystem, spec)
            match_payloads.append(
                {"type": "package_exact", "ecosystem": ecosystem, "name": name, "version": exact_version}
                if exact_version
                else {"type": "package_range", "ecosystem": ecosystem, "name": name, "version_spec": spec}
            )
        if not match_payloads:
            continue
        for match in match_payloads:
            item_id = f"{advisory_id}:{ecosystem}:{name}:{match['type']}:{match.get('version') or match.get('version_spec')}"
            item: dict[str, Any] = {
                "id": item_id,
                "kind": kind,
                "match": match,
                "action": item_action,
                "confidence": 1.0 if is_malware else 0.8,
                "reason": normalize_reason(summary, fallback=f"OSV advisory {advisory_id}."),
                "source": "osv",
                "source_refs": refs,
                "published_at": published_at,
                "modified_at": modified_at,
                "first_seen": observed_at,
                "last_seen": observed_at,
                "metadata": metadata,
            }
            if withdrawn_at:
                item["revoked_at"] = withdrawn_at
                item["revocation_reason"] = "OSV advisory withdrawn."
            items.append(item)
            for index, indicator in enumerate(indicators, start=1):
                items.append(
                    {
                        "id": f"{item_id}:indicator:{indicator['type']}:{index}",
                        "kind": f"ioc_{indicator['type']}",
                        "match": {"type": indicator["type"], "value": indicator["value"]},
                        "action": item_action,
                        "confidence": 0.9 if is_malware else 0.6,
                        "reason": normalize_reason(summary, fallback=f"OSV indicator from {advisory_id}."),
                        "source": "osv",
                        "source_refs": refs,
                        "published_at": published_at,
                        "modified_at": modified_at,
                        "first_seen": observed_at,
                        "last_seen": observed_at,
                        "metadata": {"parent_id": item_id},
                        **({"revoked_at": withdrawn_at, "revocation_reason": "OSV advisory withdrawn."} if withdrawn_at else {}),
                    }
                )
    return items


def parse_link_header(value: str | None) -> dict[str, str]:
    links: dict[str, str] = {}
    if not value:
        return links
    for part in value.split(","):
        part = part.strip()
        if not part or ";" not in part:
            continue
        url_part, *params = [section.strip() for section in part.split(";")]
        if not url_part.startswith("<") or not url_part.endswith(">"):
            continue
        url = url_part[1:-1]
        rel = None
        for param in params:
            if param.startswith("rel="):
                rel = param.split("=", 1)[1].strip('"')
                break
        if rel:
            links[rel] = url
    return links


def github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def github_malware_items_since(last_modified: str | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    params = {
        "type": "malware",
        "per_page": "100",
        "sort": "updated",
        "direction": "asc",
    }
    if last_modified:
        params["modified"] = f">={last_modified}"
    url = f"{GITHUB_API_ROOT}/advisories?{urlencode(params)}"
    observed_at = iso_now()
    advisories: list[dict[str, Any]] = []
    newest_modified = last_modified
    while url:
        payload, headers = request_json(url, headers=github_headers())
        if not isinstance(payload, list):
            raise IntelUnavailable("GitHub advisories response was not a list.")
        advisories.extend(item for item in payload if isinstance(item, dict))
        for advisory in payload:
            if not isinstance(advisory, dict):
                continue
            candidate = str(advisory.get("updated_at", "")).strip() or str(advisory.get("published_at", "")).strip()
            if candidate and (newest_modified is None or candidate > newest_modified):
                newest_modified = candidate
        url = parse_link_header(headers.get("Link")).get("next")
    items: list[dict[str, Any]] = []
    for advisory in advisories:
        items.extend(normalize_github_advisory(advisory, observed_at=observed_at))
    return items, {
        "name": "github_advisory",
        "synced_at": observed_at,
        "status": "ok",
        "last_modified": newest_modified,
        "advisory_count": len(advisories),
        "item_count": len(items),
    }


def osv_recent_malware_ids(last_modified: str | None) -> tuple[list[str], str | None]:
    response = request_text(f"{OSV_EXPORT_ROOT}/modified_id.csv", headers={"Accept": "text/plain"})
    lines = response.text.splitlines()
    ids: list[str] = []
    newest_seen = last_modified
    for index, line in enumerate(lines):
        if not line.strip() or "," not in line:
            continue
        modified, location = line.split(",", 1)
        modified = modified.strip()
        location = location.strip()
        if index == 0 and modified and (newest_seen is None or modified > newest_seen):
            newest_seen = modified
        if last_modified and modified <= last_modified:
            break
        advisory_id = location.rsplit("/", 1)[-1]
        if advisory_id.startswith("MAL-"):
            ids.append(advisory_id)
    return ids, newest_seen


def osv_vuln(advisory_id: str) -> dict[str, Any]:
    payload, _headers = request_json(f"{OSV_API_ROOT}/v1/vulns/{quote(advisory_id, safe='')}")
    if not isinstance(payload, dict):
        raise IntelUnavailable(f"OSV response for {advisory_id} was not an object.")
    return payload


def osv_malware_items_since(last_modified: str | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    advisory_ids, newest_modified = osv_recent_malware_ids(last_modified)
    observed_at = iso_now()
    advisories = [osv_vuln(advisory_id) for advisory_id in advisory_ids]
    items: list[dict[str, Any]] = []
    for advisory in advisories:
        items.extend(normalize_osv_advisory(advisory, observed_at=observed_at, action="block"))
    return items, {
        "name": "osv",
        "synced_at": observed_at,
        "status": "ok",
        "last_modified": newest_modified,
        "advisory_count": len(advisories),
        "item_count": len(items),
    }


def load_sync_state() -> dict[str, Any]:
    payload = load_json_file(sync_state_path(), default={})
    return payload if isinstance(payload, dict) else {}


def persist_sync_state(payload: dict[str, Any]) -> None:
    write_json(sync_state_path(), payload)


def current_cached_feed() -> dict[str, Any]:
    cached = load_cached_feed_envelope() or {}
    feed = cached.get("feed")
    if isinstance(feed, dict):
        return normalize_feed_artifact(feed)
    return normalize_feed_artifact({"items": []})


def sync_public_intelligence() -> dict[str, Any]:
    state = load_sync_state()
    cached = current_cached_feed()
    items_by_id = {str(item["id"]): item for item in cached.get("items", []) if isinstance(item, dict) and item.get("id")}
    sources: list[dict[str, Any]] = []

    github_state = (state.get("sources") or {}).get("github_advisory", {}) if isinstance(state.get("sources"), dict) else {}
    github_items, github_source = github_malware_items_since(github_state.get("last_modified"))
    for item in github_items:
        items_by_id[item["id"]] = item
    sources.append(github_source)

    osv_state = (state.get("sources") or {}).get("osv", {}) if isinstance(state.get("sources"), dict) else {}
    osv_items, osv_source = osv_malware_items_since(osv_state.get("last_modified"))
    for item in osv_items:
        items_by_id[item["id"]] = item
    sources.append(osv_source)

    feed = {
        "schema_version": FEED_SCHEMA_VERSION,
        "generated_at": iso_now(),
        "sources": sources,
        "items": sorted(items_by_id.values(), key=lambda item: item["id"]),
    }
    persist_feed_cache(feed, fetched_at=iso_now(), fetched_from="local_sync")
    persist_sync_state(
        {
            "updated_at": iso_now(),
            "sources": {
                "github_advisory": {"last_modified": github_source.get("last_modified")},
                "osv": {"last_modified": osv_source.get("last_modified")},
            },
        }
    )
    return feed


def export_intelligence_feed(*, output_path: str | None = None) -> dict[str, Any]:
    feed = current_cached_feed()
    if output_path:
        write_json(Path(output_path).expanduser().resolve(), feed)
    return feed


def load_remote_feed(url: str) -> dict[str, Any]:
    response = request_text(url, headers={"Accept": "application/json"})
    return load_feed_from_text(response.text, default_source="live_feed")


def runtime_feed(plugin_root: Path, feed_url: str | None) -> dict[str, Any]:
    observed_at = iso_now()
    seed_payload = json.loads((plugin_root / "data" / "seed_iocs.json").read_text(encoding="utf-8"))
    seed_feed = normalize_feed_artifact(seed_payload, observed_at=observed_at, default_source="seed_ioc")

    cached_envelope = load_cached_feed_envelope() or {}
    cached_feed = normalize_feed_artifact(cached_envelope.get("feed", {"items": []}), observed_at=observed_at, default_source="cached_feed")
    cache_timestamp = str(cached_envelope.get("fetched_at", "")).strip() or str(cached_feed.get("generated_at", "")).strip()
    selected_feed = cached_feed
    selected_from = "cache" if cached_feed.get("items") else "seed"
    warnings: list[dict[str, Any]] = []

    if feed_url:
        try:
            remote_feed = load_remote_feed(feed_url)
            persist_feed_cache(remote_feed, fetched_at=iso_now(), fetched_from=feed_url)
            cached_envelope = load_cached_feed_envelope() or {}
            cached_feed = normalize_feed_artifact(cached_envelope.get("feed", remote_feed), observed_at=observed_at, default_source="live_feed")
            cache_timestamp = str(cached_envelope.get("fetched_at", "")).strip() or iso_now()
            selected_feed = cached_feed
            selected_from = "remote"
        except IntelUnavailable as exc:
            if cached_feed.get("items"):
                warnings.append(
                    {
                        "code": "feed_refresh_failed",
                        "detail": f"Live feed refresh failed, continuing with the last good cached feed: {exc}",
                    }
                )
            else:
                warnings.append(
                    {
                        "code": "feed_refresh_failed",
                        "detail": f"Live feed refresh failed and no cached feed was available: {exc}",
                    }
                )
                selected_feed = normalize_feed_artifact({"items": []}, observed_at=observed_at, default_source="live_feed")
                selected_from = "seed"

    stale_reference = parse_timestamp(cache_timestamp) or parse_timestamp(selected_feed.get("generated_at"))
    if selected_from in {"cache", "remote"} and stale_reference is not None:
        age_seconds = (now_utc() - stale_reference).total_seconds()
        stale_seconds = stale_after_hours() * 3600
        if age_seconds >= stale_seconds:
            hours = round(age_seconds / 3600, 1)
            warnings.append(
                {
                    "code": "feed_stale",
                    "detail": (
                        f"Threat intelligence feed is stale ({hours} hours since the last good refresh). "
                        "Pounce continued with the cached feed."
                    ),
                }
            )

    merged = merge_feed_artifacts(seed_feed, selected_feed)
    return {
        "feed": merged,
        "selected_from": selected_from,
        "warnings": warnings,
        "cache_timestamp": cache_timestamp,
    }


def osv_ecosystem_name(ecosystem: str) -> str:
    normalized = normalize_ecosystem(ecosystem)
    if normalized == "pypi":
        return "PyPI"
    if normalized == "npm":
        return "npm"
    return ecosystem


def osv_query_package_version(ecosystem: str, package_name: str, version: str) -> list[dict[str, Any]]:
    query = {
        "package": {
            "ecosystem": osv_ecosystem_name(ecosystem),
            "name": package_name,
        },
        "version": version,
    }
    advisories: list[dict[str, Any]] = []
    pending_query = dict(query)
    while True:
        payload, _headers = request_json(f"{OSV_API_ROOT}/v1/querybatch", payload={"queries": [pending_query]}, method="POST")
        results = payload.get("results", []) if isinstance(payload, dict) else []
        if not isinstance(results, list) or not results:
            break
        result = results[0] if isinstance(results[0], dict) else {}
        for vuln in result.get("vulns") or []:
            if not isinstance(vuln, dict):
                continue
            advisory_id = str(vuln.get("id", "")).strip()
            if advisory_id:
                advisories.append(osv_vuln(advisory_id))
        next_page_token = str(result.get("next_page_token", "")).strip()
        if not next_page_token:
            break
        pending_query = {**query, "page_token": next_page_token}
    return advisories


def on_demand_osv_items(ecosystem: str, package_name: str, version: str) -> list[dict[str, Any]]:
    observed_at = iso_now()
    advisories = osv_query_package_version(ecosystem, package_name, version)
    items: list[dict[str, Any]] = []
    for advisory in advisories:
        advisory_id = str(advisory.get("id", "")).strip()
        items.extend(
            normalize_osv_advisory(
                advisory,
                observed_at=observed_at,
                action="block" if advisory_id.startswith("MAL-") else vulnerability_action(),
            )
        )
    return items


def query_param(url: str, name: str) -> str | None:
    parsed = urlparse(url)
    values = parse_qs(parsed.query).get(name)
    if not values:
        return None
    return values[0]
