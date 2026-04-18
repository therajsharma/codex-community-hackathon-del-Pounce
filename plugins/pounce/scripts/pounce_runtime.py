#!/usr/bin/env python3
"""Shared runtime for the Pounce plugin."""

from __future__ import annotations

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


MANAGED_BLOCK_BEGIN = "<!-- BEGIN POUNCE MANAGED BLOCK -->"
MANAGED_BLOCK_END = "<!-- END POUNCE MANAGED BLOCK -->"
LIVE_IOC_TTL = timedelta(minutes=10)
MAX_SCAN_FILE_SIZE = 512 * 1024
MAX_SCAN_FILE_COUNT = 1000
MAX_NPM_GRAPH_NODES = 250
POUNCE_HOOK_STATUS_MESSAGE = "Pounce vetting dependency command"

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
DEPENDENCY_COMMAND_PREFIXES = {
    ("npm", "install"): "npm",
    ("npm", "add"): "npm",
    ("pnpm", "add"): "npm",
    ("yarn", "add"): "npm",
    ("pip", "install"): "pypi",
    ("uv", "add"): "pypi",
    ("poetry", "add"): "pypi",
}
MECHANISM_PATTERNS = (
    (
        "mechanism_postinstall",
        re.compile(r"\bpostinstall\b", re.IGNORECASE),
        "critical",
        "block",
        "npm install-time script matched `postinstall`.",
    ),
    (
        "mechanism_prepare",
        re.compile(r"\bprepare\b", re.IGNORECASE),
        "medium",
        "warn",
        "npm install-time script matched `prepare`.",
    ),
    (
        "mechanism_pth_injection",
        re.compile(r"\.pth\b", re.IGNORECASE),
        "critical",
        "block",
        "Python persistence mechanism matched `.pth` injection.",
    ),
    (
        "mechanism_subprocess_popen",
        re.compile(r"\bsubprocess\.Popen\b", re.IGNORECASE),
        "critical",
        "block",
        "Python install-time code matched `subprocess.Popen`.",
    ),
)

_IOC_CACHE: dict[str, Any] = {"expires_at": datetime.fromtimestamp(0, tz=UTC), "items": []}
_LAST_GOOD_IOCS: list[dict[str, Any]] = []
_HTTP_CACHE: dict[str, Any] = {}
_NPM_VIEW_CACHE: dict[str, dict[str, str]] = {}


class VerificationUnavailable(Exception):
    """Raised when remote verification cannot be completed."""


@dataclass(slots=True)
class DependencyCommand:
    ecosystem: str
    name: str
    version: str | None
    original: str

    @property
    def exact(self) -> bool:
        return bool(self.version)

    @property
    def artifact(self) -> str:
        if self.version:
            separator = "==" if self.ecosystem == "pypi" else "@"
            return f"{self.name}{separator}{self.version}"
        return self.name


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
    data = load_json(plugin_root / "data" / "seed_iocs.json")
    items = data.get("items", [])
    return items if isinstance(items, list) else []


def parse_live_ioc_payload(payload: str) -> list[dict[str, Any]]:
    payload = payload.strip()
    if not payload:
        return []
    if payload.startswith("{"):
        parsed = json.loads(payload)
        if isinstance(parsed, dict):
            items = parsed.get("items", [])
            return items if isinstance(items, list) else []
    if payload.startswith("["):
        parsed = json.loads(payload)
        return parsed if isinstance(parsed, list) else []

    items: list[dict[str, Any]] = []
    for line in payload.splitlines():
        line = line.strip()
        if not line:
            continue
        parsed = json.loads(line)
        if isinstance(parsed, dict):
            items.append(parsed)
    return items


def load_live_iocs(feed_url: str | None) -> list[dict[str, Any]]:
    global _IOC_CACHE, _LAST_GOOD_IOCS

    if not feed_url:
        return []

    if _IOC_CACHE["items"] and now_utc() < _IOC_CACHE["expires_at"]:
        return list(_IOC_CACHE["items"])

    request = Request(feed_url, headers={"User-Agent": "pounce-local-plugin"})
    try:
        with urlopen(request, timeout=20) as response:
            raw = response.read().decode("utf-8")
        items = parse_live_ioc_payload(raw)
    except Exception:
        if _LAST_GOOD_IOCS:
            _IOC_CACHE = {"expires_at": now_utc() + LIVE_IOC_TTL, "items": list(_LAST_GOOD_IOCS)}
            return list(_LAST_GOOD_IOCS)
        return []

    _LAST_GOOD_IOCS = list(items)
    _IOC_CACHE = {"expires_at": now_utc() + LIVE_IOC_TTL, "items": list(items)}
    return items


def collect_iocs(plugin_root: Path) -> list[dict[str, Any]]:
    items = list(load_seed_iocs(plugin_root))
    live_items = load_live_iocs(os.getenv("POUNCE_IOC_FEED_URL"))
    items.extend(live_items)
    return items


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
) -> dict[str, Any]:
    return {
        "signal_id": signal_id,
        "signal_name": signal_name,
        "category": category,
        "severity": severity,
        "verdict_impact": verdict_impact,
        "evidence": evidence,
        "source": source,
        "artifact": artifact,
    }


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
    )


def match_package_iocs(
    items: list[dict[str, Any]],
    *,
    ecosystem: str,
    package_name: str,
    version: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    normalized_package = package_name.strip().lower()
    normalized_version = version.strip()
    for item in items:
        match = extract_match_value(item)
        if match.get("type") != "package":
            continue
        if normalize_ecosystem(match.get("ecosystem")) != ecosystem:
            continue
        if str(match.get("name", "")).lower() != normalized_package:
            continue
        if str(match.get("version", "")) != normalized_version:
            continue
        source = "live_ioc" if item in _LAST_GOOD_IOCS else "seed_ioc"
        findings.append(
            make_finding(
                signal_id=str(item.get("id", "ioc-match")),
                signal_name="exact_ioc_match",
                category="ioc",
                severity="critical",
                verdict_impact="block",
                evidence=str(item.get("reason", "Exact IOC match.")),
                source=source,
                artifact=f"{package_name}@{version}" if ecosystem == "npm" else f"{package_name}=={version}",
            )
        )
    return findings


def match_artifact_iocs(items: list[dict[str, Any]], artifacts: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lower_artifacts = [(artifact, artifact.lower()) for artifact in artifacts]
    for item in items:
        match = extract_match_value(item)
        if match.get("type") != "string":
            continue
        value = str(match.get("value", "")).strip()
        if not value:
            continue
        needle = value.lower()
        for artifact, lowered in lower_artifacts:
            if needle not in lowered:
                continue
            source = "live_ioc" if item in _LAST_GOOD_IOCS else "seed_ioc"
            findings.append(
                make_finding(
                    signal_id=str(item.get("id", "ioc-string-match")),
                    signal_name="artifact_ioc_match",
                    category="ioc",
                    severity="critical",
                    verdict_impact="block",
                    evidence=str(item.get("reason", "Artifact IOC match.")),
                    source=source,
                    artifact=value,
                )
            )
            break
    return findings


def scan_mechanisms(text: str, *, source: str, artifact: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for signal_name, pattern, severity, verdict_impact, evidence in MECHANISM_PATTERNS:
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


def check_npm_release(package_name: str, version: str, workspace: Path | None = None) -> list[dict[str, Any]]:
    artifact = f"{package_name}@{version}"
    try:
        package_index = fetch_json(
            f"https://registry.npmjs.org/{quote(package_name, safe='@/')}",
            cache_key=f"npm:{package_name}",
        )
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
        findings.extend(scan_mechanisms(script_names, source="registry", artifact=artifact))

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
            cache_key=f"pypi:{package_name}:{version}",
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
    warn_count = sum(1 for finding in findings if finding["verdict_impact"] == "warn")
    if warn_count >= 2:
        return "block"
    if warn_count >= 1:
        return "warn"
    return "allow"


def summarize_findings(verdict: str, findings: list[dict[str, Any]], artifact: str | None, mode: str) -> str:
    if not findings:
        if mode == "sweep":
            return "ALLOW: no seeded IOC match or heuristic warning was found in the workspace sweep."
        if artifact:
            return f"ALLOW: no seeded IOC match or heuristic warning was found for {artifact}."
        return "ALLOW: no seeded IOC match or heuristic warning was found."

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


def include_scan_path(workspace: Path, path: Path) -> bool:
    if path.name in TEXT_FILE_NAMES:
        return True
    if path.name.startswith("requirements") and path.suffix.lower() == ".txt":
        return True
    if path.suffix.lower() in TEXT_FILE_SUFFIXES:
        return True
    relative_parent = str(path.parent.relative_to(workspace)) if path.parent != workspace else ""
    return relative_parent in TEXT_SCAN_DIRECTORIES and path.suffix.lower() in {".yml", ".yaml"}


def should_scan_mechanisms(path: Path, workspace: Path) -> bool:
    if path.name in {"package.json", "setup.py", "pyproject.toml", "setup.cfg"}:
        return True
    if path.suffix.lower() in {".py", ".pth", ".sh", ".bash", ".zsh"}:
        return True
    relative_parent = str(path.parent.relative_to(workspace)) if path.parent != workspace else ""
    return relative_parent in TEXT_SCAN_DIRECTORIES and path.suffix.lower() in {".yml", ".yaml"}


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

        if should_scan_mechanisms(path, workspace):
            for finding in scan_mechanisms(content, source="install_scan", artifact=relative_path):
                finding["evidence"] += f" File: {relative_path}."
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


def vet_payload(payload: dict[str, Any], plugin_root: Path) -> dict[str, Any]:
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
    findings: list[dict[str, Any]] = []

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
            findings.extend(
                match_package_iocs(
                    indicators,
                    ecosystem=ecosystem,
                    package_name=package_name,
                    version=version,
                )
            )
            artifact = f"{package_name}@{version}" if ecosystem == "npm" else f"{package_name}=={version}"
            if ecosystem == "npm":
                findings.extend(check_npm_release(package_name, version, workspace))
            elif ecosystem == "pypi":
                findings.extend(check_pypi_release(package_name, version))
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

    if artifacts:
        findings.extend(match_artifact_iocs(indicators, artifacts))
        findings.extend(
            scan_mechanisms("\n".join(artifacts), source="install_scan", artifact=artifact or "artifacts")
        )

    verdict = evaluate_verdict(findings)
    checked_at = iso_now()
    summary = summarize_findings(verdict, findings, artifact, mode)
    stamp_path = None
    if workspace:
        stamp_payload = {
            "mode": mode,
            "request": payload,
            "verdict": verdict,
            "summary": summary,
            "findings": findings,
            "checked_at": checked_at,
        }
        slug_source = artifact or workspace.name
        stamp_path = write_stamp(build_stamp_path(workspace, mode, slug_source), stamp_payload)

    return {
        "verdict": verdict,
        "summary": summary,
        "findings": findings,
        "checked_at": checked_at,
        "stamp_path": stamp_path,
    }


def parse_npm_spec(spec: str) -> tuple[str, str | None]:
    if spec.startswith("@"):
        pivot = spec.rfind("@")
        slash = spec.find("/")
        if pivot > slash > 0:
            name = spec[:pivot]
            version = spec[pivot + 1 :]
            return name, version or None
        return spec, None
    if "@" not in spec:
        return spec, None
    name, version = spec.rsplit("@", 1)
    return name, version or None


def parse_python_spec(spec: str) -> tuple[str, str | None]:
    for separator in ("===", "=="):
        if separator in spec:
            name, version = spec.split(separator, 1)
            return name, version or None
    return spec, None


def extract_dependency_commands(command: str) -> list[DependencyCommand]:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return []
    if len(tokens) < 2:
        return []

    for prefix, ecosystem in DEPENDENCY_COMMAND_PREFIXES.items():
        if tuple(tokens[: len(prefix)]) != prefix:
            continue

        packages: list[DependencyCommand] = []
        for token in tokens[len(prefix) :]:
            if token.startswith("-"):
                continue
            if token in {".", ".."} or "://" in token:
                continue
            if ecosystem == "npm":
                name, version = parse_npm_spec(token)
            else:
                name, version = parse_python_spec(token)
            packages.append(
                DependencyCommand(
                    ecosystem=ecosystem,
                    name=name.strip(),
                    version=(version or "").strip() or None,
                    original=token,
                )
            )
        return packages
    return []


def assess_dependency_command(command: str, plugin_root: Path, workspace: Path) -> dict[str, Any]:
    dependencies = extract_dependency_commands(command)
    if not dependencies:
        return {"matched": False, "block": False, "message": None, "results": []}

    warnings: list[str] = []
    blocks: list[str] = []
    results: list[dict[str, Any]] = []

    for dependency in dependencies:
        if not dependency.exact:
            warnings.append(
                f"Pounce saw `{dependency.original}` without an exact version. Pin the version and run `pounce.vet`."
            )
            continue
        result = vet_payload(
            {
                "mode": "release",
                "ecosystem": dependency.ecosystem,
                "package_name": dependency.name,
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
        elif result["verdict"] == "warn":
            warnings.append(result["summary"])

    if blocks:
        return {
            "matched": True,
            "block": True,
            "message": "\n".join(blocks[:3]),
            "results": results,
        }
    if warnings:
        return {
            "matched": True,
            "block": False,
            "message": "\n".join(warnings[:3]),
            "results": results,
        }
    return {"matched": True, "block": False, "message": None, "results": results}


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


def render_workspace_hooks(installed_plugin_root: Path, existing_payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = dict(existing_payload or {})
    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
    payload["hooks"] = hooks

    entries = hooks.get("PreToolUse")
    if not isinstance(entries, list):
        entries = []

    bash_entry_index: int | None = None
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
        if entry_copy.get("matcher") == "Bash" and bash_entry_index is None:
            bash_entry_index = len(cleaned_entries)
        if filtered_hooks or entry_copy.get("matcher") == "Bash":
            cleaned_entries.append(entry_copy)

    pounce_hook = pounce_hook_definition(installed_plugin_root)
    if bash_entry_index is None:
        cleaned_entries.append({"matcher": "Bash", "hooks": [pounce_hook]})
    else:
        cleaned_entries[bash_entry_index].setdefault("hooks", [])
        cleaned_entries[bash_entry_index]["hooks"].append(pounce_hook)

    hooks["PreToolUse"] = cleaned_entries
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
