#!/usr/bin/env python3
"""Shared runtime for the Pounce plugin."""

from __future__ import annotations

import configparser
import hashlib
import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen
import tomllib

import pounce_intel


MANAGED_BLOCK_BEGIN = "<!-- BEGIN POUNCE MANAGED BLOCK -->"
MANAGED_BLOCK_END = "<!-- END POUNCE MANAGED BLOCK -->"
LIVE_IOC_TTL = timedelta(minutes=10)
MAX_SCAN_FILE_SIZE = 512 * 1024
MAX_SCAN_FILE_COUNT = 1000
MAX_NPM_GRAPH_NODES = 250
POUNCE_HOOK_STATUS_MESSAGE = "Pounce vetting dependency command"
GUARD_STATE_DIRNAME = "guard"

TEXT_FILE_NAMES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-prod.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
}
TEXT_FILE_SUFFIXES = {".pth", ".log", ".txt", ".out", ".err", ".sh", ".bash", ".zsh", ".py"}
TEXT_SCAN_DIRECTORIES = {".github/workflows"}
IGNORE_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    ".next",
    ".cache",
    ".codex",
    ".mypy_cache",
    ".pounce",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    "__pycache__",
}
LOCKFILE_NAMES = {
    "Pipfile.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "yarn.lock",
}
PACKAGE_JSON_DEPENDENCY_SECTIONS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)
COMMAND_PATTERNS = (
    (("uv", "pip", "install"), "pypi", "uv", "install"),
    (("npm", "install"), "npm", "npm", "install"),
    (("npm", "i"), "npm", "npm", "i"),
    (("npm", "add"), "npm", "npm", "add"),
    (("pnpm", "add"), "npm", "pnpm", "add"),
    (("pnpm", "up"), "npm", "pnpm", "up"),
    (("yarn", "add"), "npm", "yarn", "add"),
    (("yarn", "up"), "npm", "yarn", "up"),
    (("bun", "add"), "npm", "bun", "add"),
    (("pip", "install"), "pypi", "pip", "install"),
    (("pip3", "install"), "pypi", "pip3", "install"),
    (("uv", "add"), "pypi", "uv", "add"),
    (("poetry", "add"), "pypi", "poetry", "add"),
)
COMMAND_FLAGS_WITH_VALUES = {
    "npm": {"--tag", "--registry", "--workspace", "--prefix", "--userconfig", "-C", "-w"},
    "pnpm": {"--filter", "--dir", "--workspace-root", "-C", "-F"},
    "yarn": {"--cwd", "--mode", "--json"},
    "bun": {"--cwd", "--registry", "--filter"},
    "pip": {
        "-c",
        "--constraint",
        "-e",
        "--editable",
        "-f",
        "--find-links",
        "-i",
        "--index-url",
        "-r",
        "--requirement",
        "--extra-index-url",
        "--python",
    },
    "pip3": {
        "-c",
        "--constraint",
        "-e",
        "--editable",
        "-f",
        "--find-links",
        "-i",
        "--index-url",
        "-r",
        "--requirement",
        "--extra-index-url",
        "--python",
    },
    "uv": {"--group", "--extra", "-c", "--constraint", "-r", "--requirement", "--python"},
    "poetry": {"--group", "-G", "--source"},
}
NPM_EXACT_SAVE_FLAGS = {
    ("npm", "install"): "--save-exact",
    ("npm", "i"): "--save-exact",
    ("npm", "add"): "--save-exact",
    ("pnpm", "add"): "--save-exact",
    ("yarn", "add"): "--exact",
    ("yarn", "up"): "--exact",
    ("bun", "add"): "--exact",
}
NPM_EXACT_VERSION_RE = re.compile(r"^v?\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
PYTHON_EXACT_SPEC_RE = re.compile(r"^(?:===|==)\s*[^,*;\s]+$")
PYTHON_NAME_SPEC_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*(?:\[[^\]]+\])?)(.*)$")
VERSION_TOKEN_RE = re.compile(r"[A-Za-z]+|\d+")
MECHANISM_PATTERNS = (
    (
        "mechanism_postinstall",
        re.compile(r"\bpostinstall\b", re.IGNORECASE),
        "critical",
        "block",
        "npm install-time script matched `postinstall`.",
        frozenset({"npm_install"}),
    ),
    (
        "mechanism_prepare",
        re.compile(r"\bprepare\b", re.IGNORECASE),
        "medium",
        "warn",
        "npm install-time script matched `prepare`.",
        frozenset({"npm_install"}),
    ),
    (
        "mechanism_pth_injection",
        re.compile(r"\.pth\b", re.IGNORECASE),
        "critical",
        "block",
        "Python persistence mechanism matched `.pth` injection.",
        frozenset({"python_persistence"}),
    ),
    (
        "mechanism_subprocess_popen",
        re.compile(r"\bsubprocess\.Popen\b", re.IGNORECASE),
        "critical",
        "block",
        "Python install-time code matched `subprocess.Popen`.",
        frozenset({"python_install"}),
    ),
)

_IOC_CACHE: dict[str, Any] = {"expires_at": datetime.fromtimestamp(0, tz=UTC), "items": []}
_LAST_GOOD_IOCS: list[dict[str, Any]] = []
_HTTP_CACHE: dict[str, Any] = {}
_NPM_VIEW_CACHE: dict[str, dict[str, str]] = {}
_LAST_INTEL_CONTEXT: dict[str, Any] = {"feed": {"items": []}, "warnings": []}


class VerificationUnavailable(Exception):
    """Raised when remote verification cannot be completed."""


@dataclass(slots=True)
class DependencyCommand:
    ecosystem: str
    manager: str
    verb: str
    name: str
    version_spec: str | None
    original: str
    spec_kind: str
    segment_index: int
    token_index: int

    @property
    def exact(self) -> bool:
        return self.spec_kind == "exact"

    @property
    def version(self) -> str | None:
        return self.version_spec if self.exact else None

    @property
    def artifact(self) -> str:
        if self.version:
            separator = "==" if self.ecosystem == "pypi" else "@"
            return f"{self.name}{separator}{self.version}"
        return self.name


@dataclass(slots=True)
class DependencyCommandSegment:
    raw: str
    separator: str | None
    tokens: list[str]
    prefix_length: int
    ecosystem: str
    manager: str
    verb: str
    index: int
    dependencies: list[DependencyCommand]


def plugin_root_from_script(script_file: str | Path) -> Path:
    return Path(script_file).resolve().parent.parent


def now_utc() -> datetime:
    return datetime.now(tz=UTC)


def iso_now() -> str:
    return now_utc().isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def load_json_file(path: Path, *, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "item"


def truncate(value: str, limit: int = 240) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def fetch_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = 20,
    cache_key: str | None = None,
) -> Any:
    if cache_key and cache_key in _HTTP_CACHE:
        return _HTTP_CACHE[cache_key]

    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "pounce-local-plugin",
            **(headers or {}),
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
    except HTTPError as exc:
        raise VerificationUnavailable(f"{url} returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise VerificationUnavailable(f"{url} could not be reached: {exc.reason}") from exc

    if cache_key:
        _HTTP_CACHE[cache_key] = payload
    return payload


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    cleaned = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def normalize_ecosystem(value: str | None) -> str:
    normalized = (value or "").strip().lower()
    if normalized in {"npm", "node", "javascript"}:
        return "npm"
    if normalized in {"pypi", "python", "pip"}:
        return "pypi"
    if normalized == "mixed":
        return "mixed"
    return normalized


def load_seed_iocs(plugin_root: Path) -> list[dict[str, Any]]:
    context = pounce_intel.runtime_feed(plugin_root, None)
    feed = context.get("feed", {})
    items = feed.get("items", []) if isinstance(feed, dict) else []
    return items if isinstance(items, list) else []


def parse_live_ioc_payload(payload: str) -> list[dict[str, Any]]:
    feed = pounce_intel.load_feed_from_text(payload, default_source="live_feed")
    items = feed.get("items", []) if isinstance(feed, dict) else []
    return items if isinstance(items, list) else []


def load_live_iocs(feed_url: str | None) -> list[dict[str, Any]]:
    context = pounce_intel.runtime_feed(plugin_root_from_script(__file__), feed_url)
    feed = context.get("feed", {})
    items = feed.get("items", []) if isinstance(feed, dict) else []
    return items if isinstance(items, list) else []


def collect_iocs(plugin_root: Path) -> list[dict[str, Any]]:
    global _LAST_INTEL_CONTEXT
    _LAST_INTEL_CONTEXT = pounce_intel.runtime_feed(plugin_root, os.getenv("POUNCE_IOC_FEED_URL"))
    feed = _LAST_INTEL_CONTEXT.get("feed", {})
    items = feed.get("items", []) if isinstance(feed, dict) else []
    return list(items) if isinstance(items, list) else []


def extract_match_value(item: dict[str, Any]) -> dict[str, Any]:
    match = item.get("match", {})
    return match if isinstance(match, dict) else {}


def make_finding(
    *,
    signal_id: str,
    signal_name: str,
    category: str,
    severity: str,
    verdict_impact: str,
    evidence: str,
    source: str,
    artifact: str,
    count_toward_block: bool = True,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    finding = {
        "signal_id": signal_id,
        "signal_name": signal_name,
        "category": category,
        "severity": severity,
        "verdict_impact": verdict_impact,
        "evidence": evidence,
        "source": source,
        "artifact": artifact,
        "count_toward_block": count_toward_block,
    }
    if metadata:
        finding["metadata"] = metadata
    return finding


def normalize_artifacts(raw_artifacts: Any) -> list[str]:
    artifacts: list[str] = []
    if isinstance(raw_artifacts, str):
        artifacts.append(raw_artifacts)
    elif isinstance(raw_artifacts, list):
        for item in raw_artifacts:
            if isinstance(item, str):
                artifacts.append(item)
            else:
                artifacts.append(json.dumps(item, sort_keys=True))
    elif raw_artifacts is not None:
        artifacts.append(json.dumps(raw_artifacts, sort_keys=True))
    return [item for item in artifacts if item]


def build_verification_unavailable(
    *,
    source: str,
    artifact: str,
    detail: str,
) -> dict[str, Any]:
    return make_finding(
        signal_id="verification-unavailable",
        signal_name="verification_unavailable",
        category="verification",
        severity="medium",
        verdict_impact="warn",
        evidence=detail,
        source=source,
        artifact=artifact,
        count_toward_block=False,
    )


def build_feed_warning(detail: str, artifact: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    return make_finding(
        signal_id="intel-feed-warning",
        signal_name="intel_feed_warning",
        category="verification",
        severity="medium",
        verdict_impact="warn",
        evidence=detail,
        source="intel_feed",
        artifact=artifact,
        count_toward_block=False,
        metadata=metadata,
    )


def match_package_iocs(
    items: list[dict[str, Any]],
    *,
    ecosystem: str,
    package_name: str,
    version: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in pounce_intel.find_package_matches(
        items,
        ecosystem=ecosystem,
        package_name=package_name,
        version=version,
    ):
        action = str(item.get("action", "warn")).strip().lower()
        verdict_impact = action if action in {"warn", "block"} else "warn"
        match = extract_match_value(item)
        signal_name = "exact_ioc_match" if match.get("type") == "package_exact" else "range_ioc_match"
        metadata = pounce_intel.indicator_metadata(item)
        indicators = metadata.get("indicators") if isinstance(metadata, dict) else None
        evidence = str(item.get("reason", "Exact IOC match."))
        if isinstance(indicators, list) and indicators:
            related = ", ".join(str(entry.get("value")) for entry in indicators[:3] if isinstance(entry, dict))
            if related:
                evidence += f" Related indicators: {related}."
        findings.append(
            make_finding(
                signal_id=str(item.get("id", "ioc-match")),
                signal_name=signal_name,
                category="ioc",
                severity="critical" if verdict_impact == "block" else "medium",
                verdict_impact=verdict_impact,
                evidence=evidence,
                source=str(item.get("source", "intel_feed")),
                artifact=f"{package_name}@{version}" if ecosystem == "npm" else f"{package_name}=={version}",
                count_toward_block=verdict_impact == "block",
                metadata=metadata,
            )
        )
    return findings


def match_artifact_iocs(items: list[dict[str, Any]], artifacts: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item, _artifact in pounce_intel.find_artifact_matches(items, artifacts):
        action = str(item.get("action", "warn")).strip().lower()
        verdict_impact = action if action in {"warn", "block"} else "warn"
        match = extract_match_value(item)
        match_type = str(match.get("type", "string")).strip()
        signal_name = {
            "domain": "artifact_domain_match",
            "ip": "artifact_ip_match",
            "url": "artifact_url_match",
        }.get(match_type, "artifact_ioc_match")
        value = str(match.get("value", "")).strip() or str(item.get("id", "ioc-string-match"))
        findings.append(
            make_finding(
                signal_id=str(item.get("id", "ioc-string-match")),
                signal_name=signal_name,
                category="ioc",
                severity="critical" if verdict_impact == "block" else "medium",
                verdict_impact=verdict_impact,
                evidence=str(item.get("reason", "Artifact IOC match.")),
                source=str(item.get("source", "intel_feed")),
                artifact=value,
                count_toward_block=verdict_impact == "block",
                metadata=pounce_intel.indicator_metadata(item),
            )
        )
    return findings


def scan_mechanisms(
    text: str,
    *,
    source: str,
    artifact: str,
    contexts: set[str] | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for signal_name, pattern, severity, verdict_impact, evidence, pattern_contexts in MECHANISM_PATTERNS:
        if contexts is not None and not pattern_contexts.intersection(contexts):
            continue
        if not pattern.search(text):
            continue
        findings.append(
            make_finding(
                signal_id=signal_name,
                signal_name=signal_name,
                category="mechanism",
                severity=severity,
                verdict_impact=verdict_impact,
                evidence=evidence,
                source=source,
                artifact=artifact,
            )
        )
    return findings


def normalize_github_repo(repository_value: Any) -> str | None:
    if isinstance(repository_value, dict):
        repository_value = repository_value.get("url") or repository_value.get("repository")
    if not isinstance(repository_value, str):
        return None

    value = repository_value.strip()
    value = value.replace("git+", "")
    if value.endswith(".git"):
        value = value[:-4]
    if value.startswith("git@github.com:"):
        value = "https://github.com/" + value.split(":", 1)[1]

    parsed = urlparse(value)
    if parsed.netloc and parsed.netloc.lower() != "github.com":
        return None
    if parsed.netloc:
        path = parsed.path.strip("/")
    else:
        path = value.strip("/")
        if path.startswith("github.com/"):
            path = path.split("/", 1)[1]
    parts = [part for part in path.split("/") if part]
    if len(parts) < 2:
        return None
    return f"{parts[0]}/{parts[1]}"


def github_tag_exists(repo_slug: str, tag: str) -> bool:
    quoted = quote(tag, safe="")
    endpoints = (
        f"https://api.github.com/repos/{repo_slug}/git/ref/tags/{quoted}",
        f"https://api.github.com/repos/{repo_slug}/releases/tags/{quoted}",
    )
    last_error: str | None = None
    for endpoint in endpoints:
        try:
            request = Request(endpoint, headers={"User-Agent": "pounce-local-plugin"})
            with urlopen(request, timeout=20):
                pass
            return True
        except HTTPError as exc:
            if exc.code == 404:
                continue
            last_error = f"{endpoint} returned HTTP {exc.code}"
        except URLError as exc:
            last_error = f"{endpoint} could not be reached: {exc.reason}"
    if last_error:
        raise VerificationUnavailable(last_error)
    return False


def check_github_tag(repo_slug: str, version: str, artifact: str) -> list[dict[str, Any]]:
    candidates = (f"v{version}", version)
    for candidate in candidates:
        try:
            if github_tag_exists(repo_slug, candidate):
                return []
        except VerificationUnavailable as exc:
            return [
                build_verification_unavailable(
                    source="github",
                    artifact=artifact,
                    detail=f"GitHub tag verification was unavailable: {exc}",
                )
            ]
    return [
        make_finding(
            signal_id="github-tag-mismatch",
            signal_name="github_tag_mismatch",
            category="registry",
            severity="medium",
            verdict_impact="warn",
            evidence=f"No matching GitHub tag or release was found in {repo_slug} for version {version}.",
            source="github",
            artifact=artifact,
        )
    ]


def select_previous_npm_version(package_index: dict[str, Any], version: str) -> str | None:
    time_map = package_index.get("time", {})
    versions = package_index.get("versions", {})
    target_time = parse_timestamp(time_map.get(version))
    if not target_time:
        return None

    previous_version: str | None = None
    previous_time: datetime | None = None
    for candidate, published_at in time_map.items():
        if candidate in {"created", "modified"}:
            continue
        if candidate == version or candidate not in versions:
            continue
        parsed = parse_timestamp(published_at)
        if not parsed or parsed >= target_time:
            continue
        if previous_time is None or parsed > previous_time:
            previous_version = candidate
            previous_time = parsed
    return previous_version


def iter_nested_lock_dependencies(dependencies: Any) -> list[dict[str, Any]]:
    if not isinstance(dependencies, dict):
        return []
    items: list[dict[str, Any]] = []
    for entry in dependencies.values():
        if isinstance(entry, dict):
            items.append(entry)
            items.extend(iter_nested_lock_dependencies(entry.get("dependencies")))
    return items


def extract_npm_version_from_lockfile(lock_payload: dict[str, Any], package_name: str) -> str | None:
    packages = lock_payload.get("packages")
    if isinstance(packages, dict):
        entry = packages.get(f"node_modules/{package_name}")
        if isinstance(entry, dict):
            version = entry.get("version")
            if isinstance(version, str) and version:
                return version

    dependencies = lock_payload.get("dependencies")
    if isinstance(dependencies, dict):
        entry = dependencies.get(package_name)
        if isinstance(entry, dict):
            version = entry.get("version")
            if isinstance(version, str) and version:
                return version
        for nested in iter_nested_lock_dependencies(dependencies):
            if nested.get("name") == package_name and isinstance(nested.get("version"), str):
                return str(nested["version"])
    return None


def read_workspace_npm_lock(workspace: Path) -> tuple[Path, dict[str, Any]] | None:
    for filename in ("package-lock.json", "npm-shrinkwrap.json"):
        path = workspace / filename
        if not path.exists():
            continue
        try:
            payload = load_json(path)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return path, payload
    return None


def resolve_workspace_npm_version(workspace: Path | None, package_name: str) -> str | None:
    if workspace is None:
        return None
    lock_payload = read_workspace_npm_lock(workspace)
    if not lock_payload:
        return None
    _, payload = lock_payload
    return extract_npm_version_from_lockfile(payload, package_name)


def resolve_stamp_npm_version(workspace: Path | None, package_name: str, target_version: str) -> str | None:
    if workspace is None:
        return None
    stamp_dir = workspace / ".pounce" / "stamps"
    if not stamp_dir.exists():
        return None

    best_version: str | None = None
    best_checked_at: datetime | None = None
    for stamp_path in stamp_dir.glob("release-*.json"):
        try:
            payload = load_json(stamp_path)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict) or payload.get("verdict") == "block":
            continue
        request = payload.get("request", {})
        if not isinstance(request, dict):
            continue
        if normalize_ecosystem(request.get("ecosystem")) != "npm":
            continue
        if str(request.get("package_name", "")).strip() != package_name:
            continue
        version = str(request.get("version", "")).strip()
        if not version or version == target_version:
            continue
        checked_at = parse_timestamp(payload.get("checked_at"))
        if checked_at is None:
            checked_at = datetime.fromtimestamp(stamp_path.stat().st_mtime, tz=UTC)
        if best_checked_at is None or checked_at > best_checked_at:
            best_version = version
            best_checked_at = checked_at
    return best_version


def resolve_npm_release_baseline(
    package_index: dict[str, Any],
    package_name: str,
    version: str,
    workspace: Path | None,
) -> tuple[str | None, str | None]:
    workspace_version = resolve_workspace_npm_version(workspace, package_name)
    if workspace_version:
        return workspace_version, "workspace_lockfile"

    stamped_version = resolve_stamp_npm_version(workspace, package_name, version)
    if stamped_version:
        return stamped_version, "last_good_stamp"

    previous_version = select_previous_npm_version(package_index, version)
    if previous_version:
        return previous_version, "registry_previous_release"
    return None, None


def workspace_dependency_versions(workspace: Path | None, ecosystem: str, package_name: str) -> list[str]:
    if workspace is None or not workspace.exists():
        return []
    snapshot = collect_dependency_snapshot(workspace)
    package_key = package_name if ecosystem == "npm" else normalize_python_package_key(package_name)
    matches: list[str] = []
    for entry in (snapshot.get("files") or {}).values():
        if not isinstance(entry, dict) or entry.get("ecosystem") != ecosystem or entry.get("lockfile"):
            continue
        dependencies = entry.get("dependencies") or {}
        for key, spec in dependencies.items():
            if ecosystem == "npm":
                candidate_name = dependency_entry_name(str(key))
            else:
                candidate_name = normalize_python_package_key(dependency_entry_name(str(key)))
            if candidate_name != package_key:
                continue
            spec_value = str(spec or "").strip()
            if ecosystem == "npm":
                _, exact_spec, spec_kind = parse_npm_spec(f"{dependency_entry_name(str(key))}@{spec_value}")
            else:
                _, exact_spec, spec_kind = parse_python_spec(f"{dependency_entry_name(str(key))}{spec_value}")
            if spec_kind == "exact" and exact_spec:
                matches.append(exact_spec)
    return matches


def resolve_workspace_python_version(workspace: Path | None, package_name: str) -> str | None:
    matches = workspace_dependency_versions(workspace, "pypi", package_name)
    return matches[0] if matches else None


def resolve_stamp_python_version(workspace: Path | None, package_name: str, target_version: str) -> str | None:
    if workspace is None:
        return None
    stamp_dir = workspace / ".pounce" / "stamps"
    if not stamp_dir.exists():
        return None

    normalized_package_name = normalize_python_package_key(package_name)
    best_version: str | None = None
    best_checked_at: datetime | None = None
    for stamp_path in stamp_dir.glob("release-*.json"):
        try:
            payload = load_json(stamp_path)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict) or payload.get("verdict") == "block":
            continue
        request = payload.get("request", {})
        if not isinstance(request, dict):
            continue
        if normalize_ecosystem(request.get("ecosystem")) != "pypi":
            continue
        if normalize_python_package_key(str(request.get("package_name", ""))) != normalized_package_name:
            continue
        version = str(request.get("version", "")).strip()
        if not version or version == target_version:
            continue
        checked_at = parse_timestamp(payload.get("checked_at"))
        if checked_at is None:
            checked_at = datetime.fromtimestamp(stamp_path.stat().st_mtime, tz=UTC)
        if best_checked_at is None or checked_at > best_checked_at:
            best_version = version
            best_checked_at = checked_at
    return best_version


def pypi_release_uploaded_at(releases: dict[str, Any], version: str) -> datetime | None:
    release_entries = releases.get(version)
    if not isinstance(release_entries, list) or not release_entries:
        return None
    timestamps = [
        parse_timestamp(entry.get("upload_time_iso_8601"))
        for entry in release_entries
        if isinstance(entry, dict)
    ]
    timestamps = [timestamp for timestamp in timestamps if timestamp is not None]
    if not timestamps:
        return None
    return min(timestamps)


def select_previous_pypi_version(package_index: dict[str, Any], version: str) -> str | None:
    releases = package_index.get("releases", {})
    if not isinstance(releases, dict):
        return None
    target_time = pypi_release_uploaded_at(releases, version)
    if not target_time:
        return None

    previous_version: str | None = None
    previous_time: datetime | None = None
    for candidate in releases:
        if candidate == version:
            continue
        published_at = pypi_release_uploaded_at(releases, candidate)
        if not published_at or published_at >= target_time:
            continue
        if previous_time is None or published_at > previous_time:
            previous_version = candidate
            previous_time = published_at
    return previous_version


def resolve_pypi_release_baseline(
    package_index: dict[str, Any],
    package_name: str,
    version: str,
    workspace: Path | None,
) -> tuple[str | None, str | None]:
    workspace_version = resolve_workspace_python_version(workspace, package_name)
    if workspace_version:
        return workspace_version, "workspace_manifest"

    stamped_version = resolve_stamp_python_version(workspace, package_name, version)
    if stamped_version:
        return stamped_version, "last_good_stamp"

    previous_version = select_previous_pypi_version(package_index, version)
    if previous_version:
        return previous_version, "registry_previous_release"
    return None, None


def metadata_dependencies(metadata: dict[str, Any]) -> dict[str, str]:
    dependencies = metadata.get("dependencies") or {}
    if not isinstance(dependencies, dict):
        return {}
    return {str(name): str(spec) for name, spec in dependencies.items() if str(name).strip() and str(spec).strip()}


def npm_package_spec(package_name: str, version: str) -> str:
    return f"{package_name}@{version}"


def load_npm_view_dependencies(package_name: str, version_spec: str) -> dict[str, str]:
    cache_key = npm_package_spec(package_name, version_spec)
    if cache_key in _NPM_VIEW_CACHE:
        return dict(_NPM_VIEW_CACHE[cache_key])

    try:
        completed = subprocess.run(
            ["npm", "view", cache_key, "dependencies", "--json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
    except FileNotFoundError as exc:
        raise VerificationUnavailable("npm CLI was not available for transitive dependency analysis.") from exc
    except subprocess.TimeoutExpired as exc:
        raise VerificationUnavailable(f"npm view timed out for {cache_key}.") from exc

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or f"npm view failed for {cache_key}."
        raise VerificationUnavailable(detail)

    raw = completed.stdout.strip()
    if not raw:
        payload: Any = {}
    else:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise VerificationUnavailable(f"npm view returned invalid JSON for {cache_key}.") from exc

    if payload in {None, ""}:
        dependencies = {}
    elif isinstance(payload, dict):
        dependencies = {str(name): str(spec) for name, spec in payload.items() if str(name).strip() and str(spec).strip()}
    else:
        raise VerificationUnavailable(f"npm view returned an unexpected dependency payload for {cache_key}.")

    _NPM_VIEW_CACHE[cache_key] = dependencies
    return dict(dependencies)


def collect_npm_dependency_graph(package_name: str, version: str) -> tuple[set[str], set[str]]:
    direct_dependencies = load_npm_view_dependencies(package_name, version)
    direct_names = set(direct_dependencies.keys())
    all_names = set(direct_names)
    queue = list(direct_dependencies.items())
    visited_specs: set[tuple[str, str]] = set()

    while queue:
        dependency_name, spec = queue.pop(0)
        spec_key = (dependency_name, spec)
        if spec_key in visited_specs:
            continue
        visited_specs.add(spec_key)
        if len(visited_specs) > MAX_NPM_GRAPH_NODES:
            raise VerificationUnavailable(
                f"Transitive dependency analysis exceeded the {MAX_NPM_GRAPH_NODES} node limit."
            )
        child_dependencies = load_npm_view_dependencies(dependency_name, spec)
        for child_name, child_spec in child_dependencies.items():
            all_names.add(child_name)
            queue.append((child_name, child_spec))
    return direct_names, all_names


def build_transitive_analysis_unavailable(artifact: str, detail: str) -> dict[str, Any]:
    return make_finding(
        signal_id="transitive-analysis-unavailable",
        signal_name="transitive_analysis_unavailable",
        category="verification",
        severity="medium",
        verdict_impact="warn",
        evidence=detail,
        source="package_diff",
        artifact=artifact,
        count_toward_block=False,
    )


def check_npm_provenance_regression(
    *,
    artifact: str,
    target_metadata: dict[str, Any],
    baseline_metadata: dict[str, Any] | None,
    baseline_version: str | None,
    baseline_source: str | None,
) -> list[dict[str, Any]]:
    if not baseline_version:
        return []
    if baseline_metadata is None:
        return [
            build_verification_unavailable(
                source="registry",
                artifact=artifact,
                detail=f"Baseline npm version {baseline_version} from {baseline_source or 'baseline'} was not available in registry metadata.",
            )
        ]

    target_has_attestations = bool((target_metadata.get("dist") or {}).get("attestations"))
    baseline_has_attestations = bool((baseline_metadata.get("dist") or {}).get("attestations"))
    if target_has_attestations or not baseline_has_attestations:
        return []

    return [
        make_finding(
            signal_id="npm-provenance-regression",
            signal_name="npm_provenance_regression",
            category="provenance",
            severity="medium",
            verdict_impact="warn",
            evidence=(
                f"npm release provenance regressed: baseline {baseline_version} from "
                f"{baseline_source or 'baseline'} had attestations but {artifact} does not."
            ),
            source="registry",
            artifact=artifact,
            count_toward_block=False,
        )
    ]


def check_npm_missing_provenance(
    *,
    artifact: str,
    target_metadata: dict[str, Any],
) -> list[dict[str, Any]]:
    if (target_metadata.get("dist") or {}).get("attestations"):
        return []
    return [
        make_finding(
            signal_id="npm-missing-provenance",
            signal_name="npm_missing_provenance",
            category="provenance",
            severity="medium",
            verdict_impact="warn",
            evidence=f"npm release provenance metadata was missing for {artifact}.",
            source="registry",
            artifact=artifact,
            count_toward_block=False,
        )
    ]


def check_npm_dependency_diff(
    *,
    artifact: str,
    package_name: str,
    version: str,
    target_metadata: dict[str, Any],
    baseline_metadata: dict[str, Any] | None,
    baseline_version: str | None,
    baseline_source: str | None,
) -> list[dict[str, Any]]:
    if not baseline_version:
        return []

    findings: list[dict[str, Any]] = []
    if baseline_metadata is None:
        findings.append(
            build_verification_unavailable(
                source="package_diff",
                artifact=artifact,
                detail=f"Baseline npm version {baseline_version} from {baseline_source or 'baseline'} was not available for dependency comparison.",
            )
        )
        return findings

    baseline_direct = set(metadata_dependencies(baseline_metadata).keys())
    target_direct = set(metadata_dependencies(target_metadata).keys())
    new_direct = sorted(target_direct - baseline_direct)
    if new_direct:
        findings.append(
            make_finding(
                signal_id="workspace-dependency-churn",
                signal_name="workspace_dependency_churn",
                category="dependency_diff",
                severity="medium",
                verdict_impact="warn",
                evidence=(
                    f"New direct dependencies appeared relative to baseline {baseline_version} from "
                    f"{baseline_source or 'baseline'}: {', '.join(new_direct[:5])}."
                ),
                source="package_diff",
                artifact=artifact,
            )
        )

    try:
        _, target_all = collect_npm_dependency_graph(package_name, version)
        _, baseline_all = collect_npm_dependency_graph(package_name, baseline_version)
    except VerificationUnavailable as exc:
        findings.append(build_transitive_analysis_unavailable(artifact, str(exc)))
        return findings

    target_transitive = target_all - target_direct
    baseline_transitive = baseline_all - baseline_direct
    new_transitive = sorted(target_transitive - baseline_transitive)
    if new_transitive:
        findings.append(
            make_finding(
                signal_id="workspace-transitive-dependency-churn",
                signal_name="workspace_transitive_dependency_churn",
                category="dependency_diff",
                severity="medium",
                verdict_impact="warn",
                evidence=(
                    f"New transitive dependencies appeared relative to baseline {baseline_version} from "
                    f"{baseline_source or 'baseline'}: {', '.join(new_transitive[:5])}."
                ),
                source="package_diff",
                artifact=artifact,
            )
        )

    return findings


def check_release_age(published_at: datetime | None, artifact: str) -> list[dict[str, Any]]:
    if not published_at:
        return []
    if now_utc() - published_at >= timedelta(hours=72):
        return []
    return [
        make_finding(
            signal_id="release-age-below-72h",
            signal_name="release_age_below_72h",
            category="freshness",
            severity="medium",
            verdict_impact="warn",
            evidence="Release is newer than 72 hours and still inside the cooldown window.",
            source="registry",
            artifact=artifact,
        )
    ]


def load_npm_package_index(package_name: str) -> dict[str, Any]:
    return fetch_json(
        f"https://registry.npmjs.org/{quote(package_name, safe='@/')}",
        cache_key=f"npm:{package_name}",
    )


def load_pypi_package_index(package_name: str) -> dict[str, Any]:
    return fetch_json(
        f"https://pypi.org/pypi/{quote(package_name)}/json",
        cache_key=f"pypi-index:{normalize_python_package_key(package_name)}",
    )


def check_npm_release(package_name: str, version: str, workspace: Path | None = None) -> list[dict[str, Any]]:
    artifact = f"{package_name}@{version}"
    try:
        package_index = load_npm_package_index(package_name)
    except VerificationUnavailable as exc:
        return [build_verification_unavailable(source="registry", artifact=artifact, detail=str(exc))]

    versions = package_index.get("versions", {})
    if version not in versions:
        return [
            build_verification_unavailable(
                source="registry",
                artifact=artifact,
                detail=f"npm registry metadata for {artifact} was not available.",
            )
        ]

    metadata = versions[version]
    findings: list[dict[str, Any]] = []
    repository = normalize_github_repo(metadata.get("repository") or package_index.get("repository"))
    published_at = parse_timestamp(package_index.get("time", {}).get(version))
    baseline_version, baseline_source = resolve_npm_release_baseline(package_index, package_name, version, workspace)
    baseline_metadata = versions.get(baseline_version) if baseline_version else None

    findings.extend(check_release_age(published_at, artifact))

    if repository:
        findings.extend(check_github_tag(repository, version, artifact))

    findings.extend(
        check_npm_missing_provenance(
            artifact=artifact,
            target_metadata=metadata,
        )
    )

    findings.extend(
        check_npm_provenance_regression(
            artifact=artifact,
            target_metadata=metadata,
            baseline_metadata=baseline_metadata,
            baseline_version=baseline_version,
            baseline_source=baseline_source,
        )
    )

    scripts = metadata.get("scripts", {})
    if isinstance(scripts, dict):
        script_names = " ".join(str(key) for key in scripts.keys())
        findings.extend(
            scan_mechanisms(
                script_names,
                source="registry",
                artifact=artifact,
                contexts={"npm_install"},
            )
        )

    findings.extend(
        check_npm_dependency_diff(
            artifact=artifact,
            package_name=package_name,
            version=version,
            target_metadata=metadata,
            baseline_metadata=baseline_metadata,
            baseline_version=baseline_version,
            baseline_source=baseline_source,
        )
    )

    return findings


def check_pypi_release(package_name: str, version: str) -> list[dict[str, Any]]:
    artifact = f"{package_name}=={version}"
    try:
        payload = fetch_json(
            f"https://pypi.org/pypi/{quote(package_name)}/{quote(version)}/json",
            cache_key=f"pypi:{normalize_python_package_key(package_name)}:{version}",
        )
    except VerificationUnavailable as exc:
        return [build_verification_unavailable(source="registry", artifact=artifact, detail=str(exc))]

    info = payload.get("info", {})
    urls = payload.get("urls") or []
    findings: list[dict[str, Any]] = []
    repository = normalize_github_repo(
        (info.get("project_urls") or {}).get("Repository")
        or (info.get("project_urls") or {}).get("repository")
        or info.get("home_page")
    )

    published_at = None
    if urls:
        published_at = parse_timestamp(urls[0].get("upload_time_iso_8601"))
    findings.extend(check_release_age(published_at, artifact))

    if repository:
        findings.extend(check_github_tag(repository, version, artifact))

    return findings


def evaluate_verdict(findings: list[dict[str, Any]]) -> str:
    if any(finding["verdict_impact"] == "block" for finding in findings):
        return "block"
    warn_count = sum(
        1
        for finding in findings
        if finding["verdict_impact"] == "warn" and finding.get("count_toward_block", True)
    )
    if warn_count >= 2:
        return "block"
    if any(finding["verdict_impact"] == "warn" for finding in findings):
        return "warn"
    return "allow"


def summarize_findings(verdict: str, findings: list[dict[str, Any]], artifact: str | None, mode: str) -> str:
    if not findings:
        if mode == "sweep":
            return "ALLOW: no threat-intelligence match or heuristic warning was found in the workspace sweep."
        if artifact:
            return f"ALLOW: no threat-intelligence match or heuristic warning was found for {artifact}."
        return "ALLOW: no threat-intelligence match or heuristic warning was found."

    highlights = "; ".join(truncate(finding["evidence"], 120) for finding in findings[:3])
    subject = artifact or ("workspace sweep" if mode == "sweep" else "requested artifact")
    return f"{verdict.upper()}: {subject}: {highlights}"


def build_stamp_path(workspace: Path, mode: str, slug_source: str) -> Path:
    slug = slugify(slug_source)
    return workspace / ".pounce" / "stamps" / f"{mode}-{slug}.json"


def write_stamp(path: Path, payload: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return str(path)


def normalize_python_package_key(name: str) -> str:
    base = name.split("[", 1)[0].strip().lower()
    return re.sub(r"[-_.]+", "-", base)


def safe_guard_turn_id(turn_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", turn_id).strip("-") or "active"


def guard_state_path(workspace: Path, turn_id: str) -> Path:
    return workspace / ".pounce" / GUARD_STATE_DIRNAME / f"turn-{safe_guard_turn_id(turn_id)}.json"


def dependency_file_kind(path: Path) -> str | None:
    name = path.name
    if name == "package.json":
        return "package_json"
    if name in LOCKFILE_NAMES:
        return "lockfile"
    if name.startswith("requirements") and path.suffix.lower() == ".txt":
        return "requirements"
    if name == "pyproject.toml":
        return "pyproject"
    if name == "setup.cfg":
        return "setup_cfg"
    if name == "setup.py":
        return "setup_py"
    if name == "Pipfile":
        return "pipfile"
    return None


def dependency_file_ecosystem(path: Path) -> str:
    if path.name in {"package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"}:
        return "npm"
    return "pypi"


def is_dependency_guard_path(path: Path) -> bool:
    return dependency_file_kind(path) is not None


def hash_payload(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def normalize_dependency_text(text: str) -> str:
    lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        lines.append(line)
    return "\n".join(lines)


def dependency_entry_name(key: str) -> str:
    return key.rsplit(":", 1)[-1]


def parse_python_requirement_entry(spec: str) -> tuple[str, str]:
    candidate = spec.strip()
    if not candidate or candidate.startswith("-") or "://" in candidate:
        return "", ""
    candidate = candidate.split(";", 1)[0].strip()
    match = PYTHON_NAME_SPEC_RE.match(candidate)
    if not match:
        return "", ""
    name = match.group(1).strip()
    remainder = match.group(2).strip()
    return name, remainder


def extract_python_mapping_spec(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, bool):
        return "*" if value else ""
    if isinstance(value, dict):
        if "version" in value and value["version"] is not None:
            return str(value["version"]).strip()
        return json.dumps(value, sort_keys=True)
    if value is None:
        return ""
    return str(value).strip()


def parse_package_json_dependencies(text: str) -> dict[str, str]:
    payload = json.loads(text)
    dependencies: dict[str, str] = {}
    if not isinstance(payload, dict):
        return dependencies
    for section in PACKAGE_JSON_DEPENDENCY_SECTIONS:
        section_payload = payload.get(section)
        if not isinstance(section_payload, dict):
            continue
        for name, spec in section_payload.items():
            normalized_name = str(name).strip()
            normalized_spec = str(spec).strip() if spec is not None else ""
            if normalized_name and normalized_spec:
                dependencies[f"{section}:{normalized_name}"] = normalized_spec
    return dependencies


def parse_requirements_dependencies(text: str) -> dict[str, str]:
    dependencies: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if line.endswith("\\"):
            line = line[:-1].strip()
        name, remainder = parse_python_requirement_entry(line)
        if not name:
            continue
        dependencies[f"requirements:{name}"] = remainder
    return dependencies


def parse_pyproject_dependency_list(entries: Any, prefix: str) -> dict[str, str]:
    dependencies: dict[str, str] = {}
    if not isinstance(entries, list):
        return dependencies
    for item in entries:
        if not isinstance(item, str):
            continue
        name, spec = parse_python_requirement_entry(item)
        if not name:
            continue
        dependencies[f"{prefix}:{name}"] = spec
    return dependencies


def parse_pyproject_dependencies(text: str) -> dict[str, str]:
    payload = tomllib.loads(text)
    dependencies: dict[str, str] = {}

    project = payload.get("project")
    if isinstance(project, dict):
        dependencies.update(parse_pyproject_dependency_list(project.get("dependencies"), "project"))
        optional_dependencies = project.get("optional-dependencies")
        if isinstance(optional_dependencies, dict):
            for group_name, group_entries in optional_dependencies.items():
                dependencies.update(
                    parse_pyproject_dependency_list(group_entries, f"project.optional.{group_name}")
                )

    tool = payload.get("tool")
    if not isinstance(tool, dict):
        return dependencies
    poetry = tool.get("poetry")
    if not isinstance(poetry, dict):
        return dependencies

    poetry_dependencies = poetry.get("dependencies")
    if isinstance(poetry_dependencies, dict):
        for name, value in poetry_dependencies.items():
            normalized_name = str(name).strip()
            if not normalized_name or normalized_name.lower() == "python":
                continue
            dependencies[f"poetry:{normalized_name}"] = extract_python_mapping_spec(value)

    legacy_dev_dependencies = poetry.get("dev-dependencies")
    if isinstance(legacy_dev_dependencies, dict):
        for name, value in legacy_dev_dependencies.items():
            normalized_name = str(name).strip()
            if normalized_name:
                dependencies[f"poetry.dev:{normalized_name}"] = extract_python_mapping_spec(value)

    poetry_groups = poetry.get("group")
    if isinstance(poetry_groups, dict):
        for group_name, group_payload in poetry_groups.items():
            if not isinstance(group_payload, dict):
                continue
            group_dependencies = group_payload.get("dependencies")
            if not isinstance(group_dependencies, dict):
                continue
            for name, value in group_dependencies.items():
                normalized_name = str(name).strip()
                if normalized_name and normalized_name.lower() != "python":
                    dependencies[f"poetry.group.{group_name}:{normalized_name}"] = extract_python_mapping_spec(value)

    return dependencies


def parse_setup_cfg_requirement_block(value: str, prefix: str) -> dict[str, str]:
    dependencies: dict[str, str] = {}
    for raw_line in value.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        name, spec = parse_python_requirement_entry(line)
        if name:
            dependencies[f"{prefix}:{name}"] = spec
    return dependencies


def parse_setup_cfg_dependencies(text: str) -> dict[str, str]:
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read_string(text)
    dependencies: dict[str, str] = {}

    if parser.has_option("options", "install_requires"):
        dependencies.update(parse_setup_cfg_requirement_block(parser.get("options", "install_requires"), "install_requires"))

    if parser.has_section("options.extras_require"):
        for extra_name, extra_value in parser.items("options.extras_require"):
            dependencies.update(parse_setup_cfg_requirement_block(extra_value, f"extras_require.{extra_name}"))

    return dependencies


def parse_pipfile_dependencies(text: str) -> dict[str, str]:
    payload = tomllib.loads(text)
    dependencies: dict[str, str] = {}
    for section in ("packages", "dev-packages"):
        section_payload = payload.get(section)
        if not isinstance(section_payload, dict):
            continue
        for name, value in section_payload.items():
            normalized_name = str(name).strip()
            if normalized_name:
                dependencies[f"{section}:{normalized_name}"] = extract_python_mapping_spec(value)
    return dependencies


def parse_setup_py_dependencies(text: str) -> dict[str, str]:
    normalized = normalize_dependency_text(text)
    return {"setup.py:__raw__": normalized} if normalized else {}


def parse_dependency_file(path: Path, text: str) -> dict[str, str]:
    kind = dependency_file_kind(path)
    if kind == "package_json":
        return parse_package_json_dependencies(text)
    if kind == "requirements":
        return parse_requirements_dependencies(text)
    if kind == "pyproject":
        return parse_pyproject_dependencies(text)
    if kind == "setup_cfg":
        return parse_setup_cfg_dependencies(text)
    if kind == "pipfile":
        return parse_pipfile_dependencies(text)
    if kind == "setup_py":
        return parse_setup_py_dependencies(text)
    return {}


def iter_dependency_guard_files(workspace: Path) -> list[Path]:
    paths: list[Path] = []
    for path in sorted(workspace.rglob("*")):
        if any(part in IGNORE_DIRECTORIES for part in path.parts):
            continue
        if not path.is_file():
            continue
        if is_dependency_guard_path(path):
            paths.append(path)
    return paths


def build_dependency_snapshot_entry(workspace: Path, path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    kind = dependency_file_kind(path)
    assert kind is not None
    try:
        dependencies = parse_dependency_file(path, text)
    except (configparser.Error, json.JSONDecodeError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        dependencies = {f"{path.name}:__raw__": normalize_dependency_text(text)}

    return {
        "path": str(path.relative_to(workspace)),
        "kind": kind,
        "ecosystem": dependency_file_ecosystem(path),
        "lockfile": kind == "lockfile",
        "fingerprint": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "semantic_fingerprint": hash_payload(dependencies),
        "dependencies": dependencies,
    }


def collect_dependency_snapshot(workspace: Path) -> dict[str, Any]:
    files: dict[str, dict[str, Any]] = {}
    for path in iter_dependency_guard_files(workspace):
        entry = build_dependency_snapshot_entry(workspace, path)
        files[entry["path"]] = entry
    return {
        "captured_at": iso_now(),
        "workspace": str(workspace),
        "files": files,
    }


def snapshot_dependency_guard(workspace: Path, turn_id: str) -> str:
    state_path = guard_state_path(workspace, turn_id)
    payload = {
        "turn_id": turn_id,
        "workspace": str(workspace),
        "captured_at": iso_now(),
        "snapshot": collect_dependency_snapshot(workspace),
        "allowlist": [],
    }
    write_json(state_path, payload)
    return str(state_path)


def load_guard_state(workspace: Path, turn_id: str) -> dict[str, Any]:
    state_path = guard_state_path(workspace, turn_id)
    payload = load_json_file(state_path, default={})
    return payload if isinstance(payload, dict) else {}


def record_dependency_guard_allowlist(workspace: Path, turn_id: str, expected_mutations: list[dict[str, Any]]) -> str:
    state_path = guard_state_path(workspace, turn_id)
    payload = load_guard_state(workspace, turn_id)
    if not payload:
        payload = {
            "turn_id": turn_id,
            "workspace": str(workspace),
            "captured_at": iso_now(),
            "snapshot": collect_dependency_snapshot(workspace),
            "allowlist": [],
        }

    allowlist = payload.get("allowlist")
    if not isinstance(allowlist, list):
        allowlist = []
    seen = {json.dumps(item, sort_keys=True) for item in allowlist if isinstance(item, dict)}
    for mutation in expected_mutations:
        key = json.dumps(mutation, sort_keys=True)
        if key not in seen:
            allowlist.append(mutation)
            seen.add(key)
    payload["allowlist"] = allowlist
    write_json(state_path, payload)
    return str(state_path)


def diff_dependency_snapshots(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_files = before.get("files") or {}
    after_files = after.get("files") or {}
    manifest_changes: list[dict[str, Any]] = []
    lockfile_changes: list[dict[str, Any]] = []

    all_paths = sorted(set(before_files) | set(after_files))
    for path in all_paths:
        before_entry = before_files.get(path)
        after_entry = after_files.get(path)
        exemplar = after_entry or before_entry or {}
        if exemplar.get("lockfile"):
            if before_entry != after_entry:
                lockfile_changes.append(
                    {
                        "path": path,
                        "ecosystem": exemplar.get("ecosystem"),
                        "before": before_entry.get("fingerprint") if isinstance(before_entry, dict) else None,
                        "after": after_entry.get("fingerprint") if isinstance(after_entry, dict) else None,
                    }
                )
            continue

        before_dependencies = (before_entry or {}).get("dependencies") or {}
        after_dependencies = (after_entry or {}).get("dependencies") or {}
        if (before_entry or {}).get("semantic_fingerprint") == (after_entry or {}).get("semantic_fingerprint"):
            continue

        for key in sorted(set(before_dependencies) | set(after_dependencies)):
            before_spec = before_dependencies.get(key)
            after_spec = after_dependencies.get(key)
            if before_spec == after_spec:
                continue
            manifest_changes.append(
                {
                    "path": path,
                    "ecosystem": exemplar.get("ecosystem"),
                    "entry": key,
                    "name": dependency_entry_name(key),
                    "before": before_spec,
                    "after": after_spec,
                }
            )

    return {"manifest_changes": manifest_changes, "lockfile_changes": lockfile_changes}


def allowlist_matches_manifest_change(change: dict[str, Any], allowlist: list[dict[str, Any]]) -> bool:
    name = str(change.get("name", "")).strip()
    ecosystem = str(change.get("ecosystem", "")).strip()
    after_spec = change.get("after")
    for mutation in allowlist:
        if not isinstance(mutation, dict):
            continue
        if str(mutation.get("ecosystem", "")).strip() != ecosystem:
            continue
        if str(mutation.get("name", "")).strip() != name:
            continue
        if str(mutation.get("expected_version", "")).strip() != str(after_spec or "").strip():
            continue
        return True
    return False


def allowlist_covers_lockfile_change(change: dict[str, Any], allowlist: list[dict[str, Any]]) -> bool:
    ecosystem = str(change.get("ecosystem", "")).strip()
    return any(
        isinstance(mutation, dict) and str(mutation.get("ecosystem", "")).strip() == ecosystem
        for mutation in allowlist
    )


def summarize_dependency_guard_diff(
    unexpected_manifest_changes: list[dict[str, Any]],
    unexpected_lockfile_changes: list[dict[str, Any]],
) -> str:
    lines: list[str] = []
    for change in unexpected_manifest_changes[:5]:
        before = change.get("before")
        after = change.get("after")
        if before is None:
            detail = f"added `{change['name']}` as `{after}` in `{change['path']}`"
        elif after is None:
            detail = f"removed `{change['name']}` from `{change['path']}`"
        else:
            detail = f"changed `{change['name']}` in `{change['path']}` from `{before}` to `{after}`"
        lines.append(detail)
    for change in unexpected_lockfile_changes[:5]:
        lines.append(f"modified lockfile `{change['path']}` without a vetted same-turn install")
    return "; ".join(lines)


def assess_dependency_guard(workspace: Path, turn_id: str) -> dict[str, Any]:
    payload = load_guard_state(workspace, turn_id)
    if not payload:
        return {"block": False, "message": None, "diff": {"manifest_changes": [], "lockfile_changes": []}}

    before_snapshot = payload.get("snapshot")
    if not isinstance(before_snapshot, dict):
        return {"block": False, "message": None, "diff": {"manifest_changes": [], "lockfile_changes": []}}

    after_snapshot = collect_dependency_snapshot(workspace)
    diff = diff_dependency_snapshots(before_snapshot, after_snapshot)
    allowlist = payload.get("allowlist")
    if not isinstance(allowlist, list):
        allowlist = []

    unexpected_manifest_changes = [
        change for change in diff["manifest_changes"] if not allowlist_matches_manifest_change(change, allowlist)
    ]
    unexpected_lockfile_changes = [
        change for change in diff["lockfile_changes"] if not allowlist_covers_lockfile_change(change, allowlist)
    ]

    if not unexpected_manifest_changes and not unexpected_lockfile_changes:
        return {"block": False, "message": None, "diff": diff}

    summary = summarize_dependency_guard_diff(unexpected_manifest_changes, unexpected_lockfile_changes)
    message = (
        "Pounce found dependency-file changes that were not explained by a vetted same-turn install: "
        f"{summary}. Before stopping, either revert those edits or rerun the dependency change through "
        "`pounce.vet` and an exact install command so Pounce can record the expected mutation."
    )
    return {
        "block": True,
        "message": message,
        "diff": diff,
        "unexpected_manifest_changes": unexpected_manifest_changes,
        "unexpected_lockfile_changes": unexpected_lockfile_changes,
    }


def include_scan_path(workspace: Path, path: Path) -> bool:
    if path.name in TEXT_FILE_NAMES:
        return True
    if path.name.startswith("requirements") and path.suffix.lower() == ".txt":
        return True
    if path.suffix.lower() in TEXT_FILE_SUFFIXES:
        return True
    relative_parent = str(path.parent.relative_to(workspace)) if path.parent != workspace else ""
    return relative_parent in TEXT_SCAN_DIRECTORIES and path.suffix.lower() in {".yml", ".yaml"}


def mechanism_contexts_for_path(path: Path) -> set[str]:
    if path.name == "package.json":
        return {"npm_install"}
    if path.name in {"setup.py", "pyproject.toml", "setup.cfg"}:
        return {"python_install"}
    if path.suffix.lower() == ".pth":
        return {"python_persistence"}
    return set()


def package_name_from_lock_path(path_key: str) -> str | None:
    if "node_modules/" not in path_key:
        return None
    return path_key.rsplit("node_modules/", 1)[-1] or None


def collect_npm_lock_versions(lock_payload: dict[str, Any]) -> list[tuple[str, str]]:
    matches: list[tuple[str, str]] = []
    packages = lock_payload.get("packages")
    if isinstance(packages, dict):
        for path_key, value in packages.items():
            if not isinstance(value, dict):
                continue
            name = package_name_from_lock_path(str(path_key))
            version = str(value.get("version", "")).strip()
            if name and version:
                matches.append((name, version))
    dependencies = lock_payload.get("dependencies")
    if isinstance(dependencies, dict):
        queue = list(dependencies.items())
        while queue:
            dependency_name, value = queue.pop(0)
            if not isinstance(value, dict):
                continue
            version = str(value.get("version", "")).strip()
            if dependency_name and version:
                matches.append((str(dependency_name), version))
            nested = value.get("dependencies")
            if isinstance(nested, dict):
                queue.extend(nested.items())
    return matches


def collect_poetry_lock_versions(text: str) -> list[tuple[str, str]]:
    matches: list[tuple[str, str]] = []
    payload = tomllib.loads(text)
    packages = payload.get("package")
    if not isinstance(packages, list):
        return matches
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = normalize_python_package_key(str(entry.get("name", "")).strip())
        version = str(entry.get("version", "")).strip()
        if name and version:
            matches.append((name, version))
    return matches


def collect_pipfile_lock_versions(text: str) -> list[tuple[str, str]]:
    matches: list[tuple[str, str]] = []
    payload = json.loads(text)
    if not isinstance(payload, dict):
        return matches
    for section_name in ("default", "develop"):
        section = payload.get(section_name)
        if not isinstance(section, dict):
            continue
        for name, entry in section.items():
            version_spec = ""
            if isinstance(entry, dict):
                version_spec = str(entry.get("version", "")).strip()
            elif isinstance(entry, str):
                version_spec = entry.strip()
            if not version_spec:
                continue
            _, exact_spec, spec_kind = parse_python_spec(f"{name}{version_spec}")
            if spec_kind != "exact" or not exact_spec:
                continue
            matches.append((normalize_python_package_key(str(name)), exact_spec))
    return matches


def collect_uv_lock_versions(text: str) -> list[tuple[str, str]]:
    matches: list[tuple[str, str]] = []
    payload = tomllib.loads(text)
    packages = payload.get("package")
    if not isinstance(packages, list):
        return matches
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = normalize_python_package_key(str(entry.get("name", "")).strip())
        version = str(entry.get("version", "")).strip()
        if name and version:
            matches.append((name, version))
    return matches


def collect_python_lock_versions(workspace: Path) -> list[tuple[str, str, str]]:
    parsers = {
        "poetry.lock": collect_poetry_lock_versions,
        "Pipfile.lock": collect_pipfile_lock_versions,
        "uv.lock": collect_uv_lock_versions,
    }
    matches: list[tuple[str, str, str]] = []
    for filename, parser in parsers.items():
        path = workspace / filename
        if not path.exists():
            continue
        try:
            parsed = parser(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, tomllib.TOMLDecodeError, UnicodeDecodeError):
            continue
        relative_path = str(path.relative_to(workspace))
        for name, version in parsed:
            matches.append((name, version, relative_path))
    return matches


def collect_workspace_exact_packages(workspace: Path) -> list[tuple[str, str, str, str]]:
    packages: list[tuple[str, str, str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    snapshot = collect_dependency_snapshot(workspace)
    for path, entry in (snapshot.get("files") or {}).items():
        if not isinstance(entry, dict) or entry.get("lockfile"):
            continue
        ecosystem = str(entry.get("ecosystem", "")).strip()
        dependencies = entry.get("dependencies") or {}
        if not isinstance(dependencies, dict):
            continue
        for key, spec in dependencies.items():
            name = dependency_entry_name(str(key))
            if ecosystem == "npm":
                _, exact_spec, spec_kind = parse_npm_spec(f"{name}@{spec}")
                normalized_name = name
            else:
                _, exact_spec, spec_kind = parse_python_spec(f"{name}{spec}")
                normalized_name = normalize_python_package_key(name)
            if spec_kind != "exact" or not exact_spec:
                continue
            item = (ecosystem, normalized_name, exact_spec, path)
            if item not in seen:
                seen.add(item)
                packages.append(item)

    lock_payload = read_workspace_npm_lock(workspace)
    if lock_payload:
        lock_path, payload = lock_payload
        for name, version in collect_npm_lock_versions(payload):
            item = ("npm", name, version, str(lock_path.relative_to(workspace)))
            if item not in seen:
                seen.add(item)
                packages.append(item)
    for name, version, origin_path in collect_python_lock_versions(workspace):
        item = ("pypi", name, version, origin_path)
        if item not in seen:
            seen.add(item)
            packages.append(item)
    return packages


def scan_workspace(workspace: Path, indicators: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not workspace.exists():
        return [
            build_verification_unavailable(
                source="install_scan",
                artifact=str(workspace),
                detail=f"Workspace path does not exist: {workspace}",
                )
        ]

    scanned_files = 0
    truncated = False
    for path in sorted(workspace.rglob("*")):
        if any(part in IGNORE_DIRECTORIES for part in path.parts):
            continue
        if path.is_dir():
            continue
        if path.stat().st_size > MAX_SCAN_FILE_SIZE:
            continue
        if not include_scan_path(workspace, path):
            continue
        if scanned_files >= MAX_SCAN_FILE_COUNT:
            truncated = True
            break
        scanned_files += 1

        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        relative_path = str(path.relative_to(workspace))
        for finding in match_artifact_iocs(indicators, [content]):
            finding["evidence"] += f" File: {relative_path}."
            findings.append(finding)

        mechanism_contexts = mechanism_contexts_for_path(path)
        if mechanism_contexts:
            for finding in scan_mechanisms(
                content,
                source="install_scan",
                artifact=relative_path,
                contexts=mechanism_contexts,
            ):
                finding["evidence"] += f" File: {relative_path}."
                findings.append(finding)

    for ecosystem, package_name, version, origin_path in collect_workspace_exact_packages(workspace):
        for finding in match_package_iocs(
            indicators,
            ecosystem=ecosystem,
            package_name=package_name,
            version=version,
        ):
            finding["evidence"] += f" Observed in {origin_path}."
            findings.append(finding)

    if truncated:
        findings.append(
            make_finding(
                signal_id="sweep-truncated",
                signal_name="sweep_truncated",
                category="verification",
                severity="medium",
                verdict_impact="warn",
                evidence=(
                    f"Workspace sweep stopped after {MAX_SCAN_FILE_COUNT} files. "
                    "Narrow the workspace or rerun after excluding generated artifacts."
                ),
                source="install_scan",
                artifact=str(workspace),
                count_toward_block=False,
            )
        )

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in findings:
        key = (finding["signal_id"], finding["artifact"], finding["source"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def vet_payload(payload: dict[str, Any], plugin_root: Path, *, write_stamp_enabled: bool = True) -> dict[str, Any]:
    mode = str(payload.get("mode", "release")).strip().lower()
    ecosystem = normalize_ecosystem(payload.get("ecosystem"))
    package_name = str(payload.get("package_name", "")).strip()
    version = str(payload.get("version", "")).strip()
    reason = str(payload.get("reason", "")).strip()
    workspace_value = str(payload.get("workspace", "")).strip()
    workspace = Path(workspace_value).expanduser().resolve() if workspace_value else None
    artifacts = normalize_artifacts(payload.get("artifacts"))
    ioc_query = payload.get("ioc_query")
    if isinstance(ioc_query, str) and ioc_query:
        artifacts.append(ioc_query)
    elif isinstance(ioc_query, list):
        artifacts.extend(normalize_artifacts(ioc_query))
    if reason:
        artifacts.append(reason)

    indicators = collect_iocs(plugin_root)
    intel_warnings = list(_LAST_INTEL_CONTEXT.get("warnings", [])) if isinstance(_LAST_INTEL_CONTEXT, dict) else []
    intel_selected_from = (
        str(_LAST_INTEL_CONTEXT.get("selected_from", "")).strip()
        if isinstance(_LAST_INTEL_CONTEXT, dict)
        else ""
    ) or None
    findings: list[dict[str, Any]] = []
    recommended_version: str | None = None
    recommended_command: str | None = None
    baseline_version: str | None = None
    baseline_source: str | None = None
    next_action: str | None = None

    if mode not in {"release", "sweep"}:
        findings.append(
            make_finding(
                signal_id="invalid-mode",
                signal_name="invalid_mode",
                category="validation",
                severity="medium",
                verdict_impact="warn",
                evidence=f"Unknown mode `{mode}`. Expected `release` or `sweep`.",
                source="input",
                artifact=mode,
            )
        )
        mode = "release"

    if mode == "release":
        if package_name and version and ecosystem in {"npm", "pypi"}:
            artifact = f"{package_name}@{version}" if ecosystem == "npm" else f"{package_name}=={version}"
            findings.extend(
                match_package_iocs(
                    indicators,
                    ecosystem=ecosystem,
                    package_name=package_name,
                    version=version,
                )
            )
            try:
                osv_items = pounce_intel.on_demand_osv_items(ecosystem, package_name, version)
            except pounce_intel.IntelUnavailable as exc:
                findings.append(build_verification_unavailable(source="osv", artifact=artifact, detail=str(exc)))
            else:
                findings.extend(
                    match_package_iocs(
                        osv_items,
                        ecosystem=ecosystem,
                        package_name=package_name,
                        version=version,
                    )
                )
            if ecosystem == "npm":
                findings.extend(check_npm_release(package_name, version, workspace))
                try:
                    package_index = load_npm_package_index(package_name)
                except VerificationUnavailable:
                    package_index = None
                if isinstance(package_index, dict):
                    baseline_version, baseline_source = resolve_npm_release_baseline(
                        package_index, package_name, version, workspace
                    )
            elif ecosystem == "pypi":
                findings.extend(check_pypi_release(package_name, version))
                try:
                    package_index = load_pypi_package_index(package_name)
                except VerificationUnavailable:
                    package_index = None
                if isinstance(package_index, dict):
                    baseline_version, baseline_source = resolve_pypi_release_baseline(
                        package_index, package_name, version, workspace
                    )
        elif package_name or version:
            findings.append(
                build_verification_unavailable(
                    source="input",
                    artifact=f"{package_name} {version}".strip(),
                    detail="Release vetting requires ecosystem, package_name, and version.",
                )
            )
        artifact = (
            f"{package_name}@{version}" if ecosystem == "npm" and package_name and version else
            f"{package_name}=={version}" if ecosystem == "pypi" and package_name and version else
            package_name or version or None
        )
    else:
        artifact = str(workspace) if workspace else "workspace"
        if not workspace:
            findings.append(
                build_verification_unavailable(
                    source="input",
                    artifact="workspace",
                    detail="Sweep mode requires a workspace path.",
                )
            )
        else:
            findings.extend(scan_workspace(workspace, indicators))

    for warning in intel_warnings:
        if isinstance(warning, dict):
            findings.append(
                build_feed_warning(
                    str(warning.get("detail", "")).strip(),
                    artifact or "intel-feed",
                    metadata={
                        "intel_warning_code": str(warning.get("code", "")).strip() or None,
                        "intel_selected_from": str(warning.get("selected_from", "")).strip() or intel_selected_from,
                    },
                )
            )

    if artifacts:
        findings.extend(match_artifact_iocs(indicators, artifacts))
        findings.extend(
            scan_mechanisms("\n".join(artifacts), source="install_scan", artifact=artifact or "artifacts")
        )

    deduped_findings: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str, str]] = set()
    for finding in findings:
        key = (str(finding.get("signal_id")), str(finding.get("artifact")), str(finding.get("source")))
        if key in seen_findings:
            continue
        seen_findings.add(key)
        deduped_findings.append(finding)
    findings = deduped_findings

    verdict = evaluate_verdict(findings)
    checked_at = iso_now()
    summary = summarize_findings(verdict, findings, artifact, mode)
    stamp_path = None
    if workspace and write_stamp_enabled:
        stamp_payload = {
            "mode": mode,
            "request": payload,
            "verdict": verdict,
            "summary": summary,
            "findings": findings,
            "checked_at": checked_at,
            "recommended_version": recommended_version,
            "recommended_command": recommended_command,
            "baseline_version": baseline_version,
            "baseline_source": baseline_source,
            "next_action": next_action,
            "intel_selected_from": intel_selected_from,
        }
        slug_source = artifact or workspace.name
        stamp_path = write_stamp(build_stamp_path(workspace, mode, slug_source), stamp_payload)

    return {
        "verdict": verdict,
        "summary": summary,
        "findings": findings,
        "checked_at": checked_at,
        "stamp_path": stamp_path,
        "recommended_version": recommended_version,
        "recommended_command": recommended_command,
        "baseline_version": baseline_version,
        "baseline_source": baseline_source,
        "next_action": next_action,
        "intel_selected_from": intel_selected_from,
    }


def split_shell_segments(command: str) -> list[tuple[str, str | None]]:
    segments: list[tuple[str, str | None]] = []
    buffer: list[str] = []
    in_single = False
    in_double = False
    index = 0

    while index < len(command):
        char = command[index]
        next_two = command[index : index + 2]
        previous = command[index - 1] if index > 0 else ""

        if char == "'" and not in_double:
            in_single = not in_single
            buffer.append(char)
            index += 1
            continue
        if char == '"' and not in_single and previous != "\\":
            in_double = not in_double
            buffer.append(char)
            index += 1
            continue

        if not in_single and not in_double:
            if next_two in {"&&", "||"}:
                raw = "".join(buffer).strip()
                if raw:
                    segments.append((raw, next_two))
                buffer = []
                index += 2
                continue
            if char == ";" or (char == "\n" and previous != "\\"):
                raw = "".join(buffer).strip()
                if raw:
                    segments.append((raw, "\n" if char == "\n" else char))
                buffer = []
                index += 1
                continue

        buffer.append(char)
        index += 1

    tail = "".join(buffer).strip()
    if tail:
        segments.append((tail, None))
    elif segments and segments[-1][1] is not None:
        segments[-1] = (segments[-1][0], None)
    return segments


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


def classify_npm_spec(version_spec: str | None) -> str:
    if not version_spec:
        return "unpinned"
    spec = version_spec.strip()
    if not spec or spec == "*":
        return "unpinned"
    if NPM_EXACT_VERSION_RE.fullmatch(spec):
        return "exact"
    return "range"


def parse_npm_spec(spec: str) -> tuple[str, str | None, str]:
    token = spec.strip()
    if token.startswith("@"):
        pivot = token.rfind("@")
        slash = token.find("/")
        if pivot > slash > 0:
            name = token[:pivot]
            version_spec = token[pivot + 1 :] or None
            return name, version_spec, classify_npm_spec(version_spec)
        return token, None, "unpinned"
    if "@" not in token:
        return token, None, "unpinned"
    name, version_spec = token.rsplit("@", 1)
    version_spec = version_spec or None
    return name, version_spec, classify_npm_spec(version_spec)


def classify_python_spec(version_spec: str | None) -> str:
    if not version_spec:
        return "unpinned"
    spec = version_spec.strip()
    if not spec or spec == "*":
        return "unpinned"
    if PYTHON_EXACT_SPEC_RE.fullmatch(spec):
        return "exact"
    return "range"


def parse_python_spec(spec: str) -> tuple[str, str | None, str]:
    name, version_spec = parse_python_requirement_entry(spec)
    if not name:
        return spec.strip(), None, "unpinned"
    normalized_spec = version_spec or None
    spec_kind = classify_python_spec(normalized_spec)
    if spec_kind == "exact" and normalized_spec:
        for separator in ("===", "=="):
            if normalized_spec.startswith(separator):
                normalized_spec = normalized_spec[len(separator) :].strip()
                break
    return name, normalized_spec, spec_kind


def flag_takes_value(manager: str, token: str) -> bool:
    if "=" in token:
        return False
    return token in COMMAND_FLAGS_WITH_VALUES.get(manager, set())


def extract_dependency_segments(command: str) -> list[DependencyCommandSegment]:
    segments: list[DependencyCommandSegment] = []
    for index, (raw, separator) in enumerate(split_shell_segments(command)):
        try:
            tokens = shlex.split(raw)
        except ValueError:
            continue
        if not tokens:
            continue

        matched_pattern: tuple[tuple[str, ...], str, str, str] | None = None
        for pattern in COMMAND_PATTERNS:
            prefix, ecosystem, manager, verb = pattern
            if tuple(tokens[: len(prefix)]) == prefix:
                matched_pattern = (prefix, ecosystem, manager, verb)
                break
        if matched_pattern is None:
            continue

        prefix, ecosystem, manager, verb = matched_pattern
        dependencies: list[DependencyCommand] = []
        token_index = len(prefix)
        while token_index < len(tokens):
            token = tokens[token_index]
            if token.startswith("-"):
                if flag_takes_value(manager, token) and token_index + 1 < len(tokens):
                    token_index += 2
                else:
                    token_index += 1
                continue
            if token in {".", ".."} or "://" in token:
                token_index += 1
                continue
            if ecosystem == "npm":
                name, version_spec, spec_kind = parse_npm_spec(token)
            else:
                name, version_spec, spec_kind = parse_python_spec(token)
            if name.strip():
                dependencies.append(
                    DependencyCommand(
                        ecosystem=ecosystem,
                        manager=manager,
                        verb=verb,
                        name=name.strip(),
                        version_spec=(version_spec or "").strip() or None,
                        original=token,
                        spec_kind=spec_kind,
                        segment_index=index,
                        token_index=token_index,
                    )
                )
            token_index += 1

        if dependencies:
            segments.append(
                DependencyCommandSegment(
                    raw=raw,
                    separator=separator,
                    tokens=tokens,
                    prefix_length=len(prefix),
                    ecosystem=ecosystem,
                    manager=manager,
                    verb=verb,
                    index=index,
                    dependencies=dependencies,
                )
            )
    return segments


def extract_dependency_commands(command: str) -> list[DependencyCommand]:
    commands: list[DependencyCommand] = []
    for segment in extract_dependency_segments(command):
        commands.extend(segment.dependencies)
    return commands


def normalize_comparison_version(version: str) -> tuple[int, int, int]:
    match = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", version.strip())
    if not match:
        return 0, 0, 0
    return int(match.group(1)), int(match.group(2) or 0), int(match.group(3) or 0)


def increment_version(version: tuple[int, int, int], field: str) -> tuple[int, int, int]:
    major, minor, patch = version
    if field == "major":
        return major + 1, 0, 0
    if field == "minor":
        return major, minor + 1, 0
    return major, minor, patch + 1


def format_version_tuple(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def npm_version_satisfies(version: str, spec: str | None, dist_tags: dict[str, Any] | None = None) -> bool:
    if not spec or spec.strip() in {"", "*"}:
        return True
    candidate = version.strip()
    requested = spec.strip()
    if requested in (dist_tags or {}):
        return str((dist_tags or {})[requested]).strip() == candidate
    if requested == "latest":
        return True
    if "||" in requested:
        return any(npm_version_satisfies(candidate, part.strip(), dist_tags) for part in requested.split("||"))
    if requested.startswith("^"):
        lower = normalize_comparison_version(requested[1:])
        if compare_versions(candidate, format_version_tuple(lower)) < 0:
            return False
        if lower[0] > 0:
            upper = increment_version(lower, "major")
        elif lower[1] > 0:
            upper = increment_version(lower, "minor")
        else:
            upper = increment_version(lower, "patch")
        return compare_versions(candidate, format_version_tuple(upper)) < 0
    if requested.startswith("~"):
        lower = normalize_comparison_version(requested[1:])
        if compare_versions(candidate, format_version_tuple(lower)) < 0:
            return False
        parts = requested[1:].split(".")
        if len(parts) <= 1:
            upper = increment_version(lower, "major")
        else:
            upper = increment_version(lower, "minor")
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
    if any(requested.startswith(prefix) for prefix in (">=", "<=", ">", "<")) or " " in requested:
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
    requested = spec.strip()
    if " " in requested and "," not in requested and not requested.startswith(("==", "===", ">=", "<=", "~=", "!=", ">", "<")):
        return False
    clauses = [clause.strip() for clause in requested.split(",") if clause.strip()]
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
            parts = boundary.split(".")
            if len(parts) >= 3:
                upper = (lower[0], lower[1] + 1, 0)
            else:
                upper = (lower[0] + 1, 0, 0)
            if compare_versions(candidate, format_version_tuple(upper)) >= 0:
                return False
    return True


def package_release_sort_key(version: str, published_at: datetime | None) -> tuple[Any, ...]:
    timestamp = published_at.timestamp() if published_at else 0.0
    return (timestamp, version_sort_key(version))


def build_exact_dependency_token(dependency: DependencyCommand, version: str) -> str:
    if dependency.ecosystem == "npm":
        return f"{dependency.name}@{version}"
    return f"{dependency.name}=={version}"


def evaluate_recommendation_candidate(
    dependency: DependencyCommand,
    candidate_version: str,
    plugin_root: Path,
    workspace: Path,
) -> dict[str, Any]:
    package_name = dependency.name if dependency.ecosystem == "npm" else dependency.name.split("[", 1)[0]
    return vet_payload(
        {
            "mode": "release",
            "ecosystem": dependency.ecosystem,
            "package_name": package_name,
            "version": candidate_version,
            "workspace": str(workspace),
            "reason": f"Remediation rewrite for `{dependency.original}`.",
            "artifacts": [dependency.original],
        },
        plugin_root,
        write_stamp_enabled=False,
    )


def recommend_vetted_version(dependency: DependencyCommand, plugin_root: Path, workspace: Path) -> dict[str, Any]:
    baseline_version: str | None = None
    baseline_source: str | None = None
    recommended_version: str | None = None
    package_name = dependency.name if dependency.ecosystem == "npm" else dependency.name.split("[", 1)[0]

    try:
        if dependency.ecosystem == "npm":
            package_index = load_npm_package_index(package_name)
            dist_tags = package_index.get("dist-tags", {}) if isinstance(package_index, dict) else {}
            versions = package_index.get("versions", {}) if isinstance(package_index, dict) else {}
            candidate_versions = [
                version
                for version in versions
                if npm_version_satisfies(version, dependency.version_spec, dist_tags if isinstance(dist_tags, dict) else {})
            ]
            candidate_versions.sort(
                key=lambda version: package_release_sort_key(
                    version, parse_timestamp((package_index.get("time", {}) or {}).get(version))
                ),
                reverse=True,
            )
            if candidate_versions:
                baseline_version, baseline_source = resolve_npm_release_baseline(
                    package_index, package_name, candidate_versions[0], workspace
                )
        else:
            package_index = load_pypi_package_index(package_name)
            releases = package_index.get("releases", {}) if isinstance(package_index, dict) else {}
            candidate_versions = [
                version
                for version in releases
                if python_version_satisfies(version, dependency.version_spec)
            ]
            candidate_versions.sort(
                key=lambda version: package_release_sort_key(version, pypi_release_uploaded_at(releases, version)),
                reverse=True,
            )
            if candidate_versions:
                baseline_version, baseline_source = resolve_pypi_release_baseline(
                    package_index, package_name, candidate_versions[0], workspace
                )
    except VerificationUnavailable:
        candidate_versions = []

    for candidate_version in candidate_versions:
        result = evaluate_recommendation_candidate(dependency, candidate_version, plugin_root, workspace)
        if result["verdict"] == "allow":
            recommended_version = candidate_version
            break

    return {
        "recommended_version": recommended_version,
        "baseline_version": baseline_version,
        "baseline_source": baseline_source,
        "next_action": "rewrite_command" if recommended_version else "manual_review",
    }


def build_recommended_command(
    command: str,
    segments: list[DependencyCommandSegment],
    replacements: dict[tuple[int, int], str],
) -> str | None:
    if not replacements:
        return None

    rewritten_segments: dict[int, str] = {}
    for segment in segments:
        segment_replacements = {
            token_index: version
            for (segment_index, token_index), version in replacements.items()
            if segment_index == segment.index
        }
        if not segment_replacements:
            continue
        tokens = list(segment.tokens)
        for token_index, version in segment_replacements.items():
            dependency = next(dep for dep in segment.dependencies if dep.token_index == token_index)
            tokens[token_index] = build_exact_dependency_token(dependency, version)
        exact_flag = NPM_EXACT_SAVE_FLAGS.get((segment.manager, segment.verb))
        if exact_flag and exact_flag not in tokens:
            tokens.append(exact_flag)
        rewritten_segments[segment.index] = shlex.join(tokens)

    pieces: list[str] = []
    for index, (raw, separator) in enumerate(split_shell_segments(command)):
        pieces.append(rewritten_segments.get(index, raw.strip()))
        if separator == "\n":
            pieces.append("\n")
        elif separator:
            pieces.append(f" {separator} ")
    return "".join(pieces).strip()


def assess_dependency_command(command: str, plugin_root: Path, workspace: Path) -> dict[str, Any]:
    segments = extract_dependency_segments(command)
    dependencies = [dependency for segment in segments for dependency in segment.dependencies]
    if not dependencies:
        return {"matched": False, "block": False, "message": None, "results": [], "expected_mutations": []}

    warnings: list[str] = []
    blocks: list[str] = []
    results: list[dict[str, Any]] = []
    expected_mutations: list[dict[str, Any]] = []
    recommended_rewrites: dict[tuple[int, int], str] = {}
    non_exact_result_indexes: list[int] = []

    for dependency in dependencies:
        if not dependency.exact:
            recommendation = recommend_vetted_version(dependency, plugin_root, workspace)
            result = {
                "verdict": "warn",
                "summary": f"Pounce blocked non-exact dependency spec `{dependency.original}`.",
                "findings": [],
                "checked_at": iso_now(),
                "stamp_path": None,
                "recommended_version": recommendation["recommended_version"],
                "recommended_command": None,
                "baseline_version": recommendation["baseline_version"],
                "baseline_source": recommendation["baseline_source"],
                "next_action": recommendation["next_action"],
            }
            results.append(result)
            non_exact_result_indexes.append(len(results) - 1)
            if recommendation["recommended_version"]:
                recommended_rewrites[(dependency.segment_index, dependency.token_index)] = recommendation["recommended_version"]
            continue

        package_name = dependency.name if dependency.ecosystem == "npm" else dependency.name.split("[", 1)[0]
        result = vet_payload(
            {
                "mode": "release",
                "ecosystem": dependency.ecosystem,
                "package_name": package_name,
                "version": dependency.version,
                "workspace": str(workspace),
                "reason": f"Hook inspection of `{command}`.",
                "artifacts": [command],
            },
            plugin_root,
        )
        results.append(result)
        if result["verdict"] == "block":
            blocks.append(result["summary"])
            continue
        if result["verdict"] == "warn":
            warnings.append(result["summary"])
        if dependency.version:
            expected_mutations.append(
                {
                    "ecosystem": dependency.ecosystem,
                    "manager": dependency.manager,
                    "verb": dependency.verb,
                    "name": dependency.name,
                    "expected_version": dependency.version,
                    "command": command,
                }
            )

    recommended_command = build_recommended_command(command, segments, recommended_rewrites)
    for index in non_exact_result_indexes:
        results[index]["recommended_command"] = recommended_command

    if non_exact_result_indexes:
        if recommended_command:
            blocks.append(
                f"Pounce blocked non-exact dependency installs. Rewrite the command to `{recommended_command}`."
            )
        else:
            blocks.append(
                "Pounce blocked non-exact dependency installs. No vetted exact rewrite was available, so manual review is required."
            )

    if blocks:
        return {
            "matched": True,
            "block": True,
            "message": "\n".join(blocks[:3]),
            "results": results,
            "expected_mutations": expected_mutations,
            "recommended_command": recommended_command,
            "next_action": "rewrite_command" if recommended_command else "manual_review",
        }
    if warnings:
        return {
            "matched": True,
            "block": False,
            "message": "\n".join(warnings[:3]),
            "results": results,
            "expected_mutations": expected_mutations,
            "recommended_command": recommended_command,
            "next_action": None,
        }
    return {
        "matched": True,
        "block": False,
        "message": None,
        "results": results,
        "expected_mutations": expected_mutations,
        "recommended_command": recommended_command,
        "next_action": None,
    }


def agents_block_text() -> str:
    return f"""{MANAGED_BLOCK_BEGIN}
## Pounce Policy

- Before proposing, writing, or running dependency-affecting changes, call `pounce.vet`.
- Treat `package.json`, lockfiles, `requirements*.txt`, `pyproject.toml`, `setup.py`, `setup.cfg`, `Pipfile`, `poetry.lock`, and install commands as dependency-affecting.
- Use `mode: "release"` for exact package/version checks and recommendation workflows.
- Use `mode: "sweep"` with the workspace path for onboarding or incident-response scans.
- If `pounce.vet` returns `block`, do not install or recommend that dependency. Propose a safer exact version or no dependency.
- If `pounce.vet` returns `warn`, explain the warning and prefer a safer exact version before proceeding.
- Prefer exact versions over floating ranges whenever Pounce is active.
{MANAGED_BLOCK_END}"""


def replace_managed_block(existing: str, managed_block: str) -> str:
    pattern = re.compile(
        rf"{re.escape(MANAGED_BLOCK_BEGIN)}.*?{re.escape(MANAGED_BLOCK_END)}",
        re.DOTALL,
    )
    if pattern.search(existing):
        updated = pattern.sub(managed_block, existing)
    else:
        updated = existing.rstrip() + ("\n\n" if existing.strip() else "") + managed_block + "\n"
    return updated


def pounce_hook_command(installed_plugin_root: Path) -> str:
    hook_script = installed_plugin_root / "scripts" / "pounce_hook.py"
    return f'python3 "{hook_script}"'


def pounce_hook_definition(installed_plugin_root: Path) -> dict[str, Any]:
    return {
        "type": "command",
        "command": pounce_hook_command(installed_plugin_root),
        "statusMessage": POUNCE_HOOK_STATUS_MESSAGE,
    }


def is_pounce_hook(hook: Any) -> bool:
    if not isinstance(hook, dict):
        return False
    command = str(hook.get("command", ""))
    status_message = str(hook.get("statusMessage", ""))
    return "pounce_hook.py" in command or status_message == POUNCE_HOOK_STATUS_MESSAGE


def ensure_pounce_hook_event(
    hooks: dict[str, Any],
    event_name: str,
    installed_plugin_root: Path,
    *,
    matcher: str | None = None,
) -> None:
    entries = hooks.get(event_name)
    if not isinstance(entries, list):
        entries = []

    target_entry_index: int | None = None
    cleaned_entries: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_copy = dict(entry)
        hook_items = entry_copy.get("hooks")
        if not isinstance(hook_items, list):
            hook_items = []
        filtered_hooks = [hook for hook in hook_items if not is_pounce_hook(hook)]
        entry_copy["hooks"] = filtered_hooks
        entry_matcher = entry_copy.get("matcher")
        if matcher is None:
            if target_entry_index is None and not entry_matcher:
                target_entry_index = len(cleaned_entries)
        elif entry_matcher == matcher and target_entry_index is None:
            target_entry_index = len(cleaned_entries)
        if filtered_hooks or entry_matcher == matcher or (matcher is None and not entry_matcher):
            cleaned_entries.append(entry_copy)

    pounce_hook = pounce_hook_definition(installed_plugin_root)
    if target_entry_index is None:
        new_entry: dict[str, Any] = {"hooks": [pounce_hook]}
        if matcher is not None:
            new_entry["matcher"] = matcher
        cleaned_entries.append(new_entry)
    else:
        cleaned_entries[target_entry_index].setdefault("hooks", [])
        cleaned_entries[target_entry_index]["hooks"].append(pounce_hook)

    hooks[event_name] = cleaned_entries


def render_workspace_hooks(installed_plugin_root: Path, existing_payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = dict(existing_payload or {})
    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
    payload["hooks"] = hooks

    ensure_pounce_hook_event(hooks, "PreToolUse", installed_plugin_root, matcher="Bash")
    ensure_pounce_hook_event(hooks, "UserPromptSubmit", installed_plugin_root)
    ensure_pounce_hook_event(hooks, "Stop", installed_plugin_root)
    return {
        **payload,
        "hooks": hooks,
    }


def ensure_workspace_config_toml(config_path: Path) -> None:
    content = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    if "[features]" not in content:
        content = content.rstrip() + ("\n\n" if content.strip() else "") + "[features]\n"
    if re.search(r"(?m)^codex_hooks\s*=", content):
        content = re.sub(r"(?m)^codex_hooks\s*=.*$", "codex_hooks = true", content)
    else:
        content = re.sub(r"(?m)^\[features\]\s*$", "[features]\ncodex_hooks = true", content, count=1)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(content.rstrip() + "\n", encoding="utf-8")
