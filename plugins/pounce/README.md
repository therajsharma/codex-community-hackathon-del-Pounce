# Pounce

Pounce is a local Codex plugin for dependency vetting, onboarding sweeps, shell-time supply-chain guardrails, same-turn dependency-file enforcement, and near-real-time malicious-package intelligence.

The Codex-native visibility surface is `pounce.dashboard`: ask the agent to show the Pounce dashboard and it will render a structured markdown snapshot of workspace protection, feed status, and recent verdicts directly in chat.

## Why it is demo-ready

Pounce is built for the exact place where AI coding agents create supply-chain risk: dependency changes. The current project already supports:

- exact release vetting for npm and PyPI
- shell-time interception for `npm`, `pnpm`, `yarn`, `bun`, `pip`, `pip3`, `uv`, and `poetry`
- exact-version rewrite guidance for non-exact install commands
- same-turn dependency guardrails for manifest and lockfile edits
- workspace sweeps for malicious package indicators
- shell-time blocking of risky dependency install commands
- chat-native dashboard snapshots over the MCP surface
- managed workspace hooks and policy injection
- refreshable threat-intelligence feeds with bundled fallback data

For a hackathon presentation, the fastest path is:

```bash
python3 plugins/pounce/scripts/install_local.py --workspace "$(pwd)"
python3 plugins/pounce/scripts/pounce_demo.py
pytest -q
```

Then in Codex, ask:

```text
Show the Pounce dashboard for this workspace
```

Presentation docs:

- [`docs/pounce-final-spec.md`](../../docs/pounce-final-spec.md)
- [`docs/hackathon-demo.md`](../../docs/hackathon-demo.md)

## Local install

From the repository root:

```bash
python3 plugins/pounce/scripts/install_local.py --workspace "$(pwd)"
```

This setup flow does six things:

1. syncs the source plugin to `~/.codex/plugins/pounce`
2. writes `~/.codex/plugins/pounce/.mcp.json` so Codex can start the local MCP server
3. writes `~/.codex/plugins/pounce/hooks.json` for plugin metadata and hook registration
4. creates or updates `~/.agents/plugins/marketplace.json`
5. injects the managed Pounce block into the workspace `AGENTS.md`
6. writes or updates workspace `.codex/hooks.json` and `.codex/config.toml` so shell-time vetting does not depend on bundled plugin hooks

## MCP tools

Pounce currently exposes two MCP tools:

- `pounce.vet`: vets an exact release, suspicious artifacts, or a workspace sweep
- `pounce.dashboard`: renders workspace protection status, feed source and warnings, and recent vet or sweep verdicts

`pounce.dashboard` reports workspace protection as:

- `protected`: managed policy present, all three workspace hook events configured, and `codex_hooks = true`
- `partial`: a workspace was resolved, but policy or hooks are incomplete
- `unavailable`: no usable workspace could be resolved

Feed selection in the dashboard is reported as one of:

- `remote`
- `remote_cache`
- `local_sync_cache`
- `seed`

The dashboard also reports:

- `trust_state`: whether the active feed came from the bundled seed, local sync cache, hosted cache, or a live hosted fetch
- `transport_policy`: the hosted-feed boundary, currently HTTPS-only with redirects disabled and a 5 MiB response cap

## Hook-enforced workflow

The installed workspace hooks enforce a three-stage flow:

1. `UserPromptSubmit` snapshots dependency manifests and lockfiles for the current turn.
2. `PreToolUse` inspects Bash dependency commands, blocks known-bad releases, and blocks non-exact specs until the command is rewritten to an exact version.
3. `Stop` compares the current dependency files against the turn snapshot and blocks unexplained edits that were not recorded as expected mutations from a vetted install.

When verification is degraded, `pounce.vet` stays available but returns `verification_status = "degraded"` and `manual_review_required = true`. Hook-enforced installs fail closed in that state.

When Pounce can recommend a vetted exact rewrite, it returns a concrete command such as:

```bash
npm i demo@1.2.0 --save-exact
pip3 install demo==1.5.0
```

Same-turn allowlisting is automatic only after the install command itself passes Pounce checks.

## Dependency files and scans

The dependency guard snapshots and compares:

- `package.json`
- `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`
- `requirements*.txt`
- `pyproject.toml`
- `setup.py`, `setup.cfg`
- `Pipfile`, `Pipfile.lock`
- `poetry.lock`
- `uv.lock`

Workspace sweep mode also scans supported text files such as logs, shell scripts, Python files, and `.github/workflows/*.yml` or `.yaml` for IOC strings and install-time execution mechanisms.

## Threat intelligence sources

Pounce consumes three intelligence layers:

1. bundled `data/seed_iocs.json` for built-in fallback coverage
2. locally synced normalized feed state under `~/.codex/pounce` by default
3. optional hosted normalized feed JSON from `POUNCE_IOC_FEED_URL`

The public upstreams used for local sync are:

- GitHub Global Security Advisories via the official REST API with `type=malware`
- OSV API plus OSV data exports, including `modified_id.csv`
- OpenSSF Malicious Packages as distributed through OSV

Pounce treats confirmed malicious-package intelligence separately from warning-only vulnerability and provenance signals.

## Normalized feed schema

Hosted and cached feeds use this normalized JSON shape:

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-04-18T12:00:00Z",
  "sources": [
    {
      "name": "osv",
      "status": "ok",
      "synced_at": "2026-04-18T12:00:00Z",
      "last_modified": "2026-04-18T11:55:00Z",
      "item_count": 42
    }
  ],
  "items": [
    {
      "id": "MAL-2026-1:npm:demo:package_exact:1.2.3",
      "kind": "malicious_package",
      "match": {
        "type": "package_exact",
        "ecosystem": "npm",
        "name": "demo",
        "version": "1.2.3"
      },
      "action": "block",
      "confidence": 1.0,
      "reason": "Known malicious package.",
      "source": "osv",
      "source_refs": [
        {"kind": "osv", "id": "MAL-2026-1"},
        {"kind": "url", "url": "https://osv.dev/vulnerability/MAL-2026-1"}
      ],
      "published_at": "2026-04-18T11:00:00Z",
      "modified_at": "2026-04-18T11:55:00Z",
      "first_seen": "2026-04-18T12:00:00Z",
      "last_seen": "2026-04-18T12:00:00Z",
      "metadata": {
        "indicators": [
          {"match_type": "url", "value": "https://evil.example/install.sh"}
        ]
      }
    }
  ]
}
```

Required per-item fields:

- `id`
- `kind`
- `match`
- `action`
- `confidence`
- `reason`
- `source`
- `source_refs`
- `published_at`
- `modified_at`
- `first_seen`
- `last_seen`

Optional lifecycle fields:

- `expires_at`
- `revoked_at`
- `revocation_reason`

Supported `match.type` values:

- `package_exact`
- `package_range`
- `string`
- `domain`
- `ip`
- `url`

Bundled legacy `seed_iocs.json` is still accepted and normalized at load time, but the normalized feed is now the first-class format.

## Sync and export workflow

Refresh local intelligence state:

```bash
python3 plugins/pounce/scripts/pounce_feed.py sync
```

Refresh local intelligence state and also write a feed artifact:

```bash
python3 plugins/pounce/scripts/pounce_feed.py sync --output /tmp/pounce-feed.json
```

Export the current normalized artifact without refreshing upstream data:

```bash
python3 plugins/pounce/scripts/pounce_feed.py export --output /tmp/pounce-feed.json
```

That exported JSON can be hosted behind `POUNCE_IOC_FEED_URL`.

## Cache and state behavior

Pounce stores shared per-user intelligence state under `~/.codex/pounce` by default:

- `feed.json`: last good normalized feed
- `state.json`: upstream sync checkpoints

Runtime behavior:

- uses bundled seed data even if no live feed is available
- prefers a fresh hosted feed when `POUNCE_IOC_FEED_URL` is set
- falls back to the last good cached feed on network failure
- warns when the cached feed is stale

The default stale threshold is 6 hours.

## Environment variables

- `POUNCE_IOC_FEED_URL`: optional hosted normalized feed artifact
- `POUNCE_STATE_DIR`: override the shared intelligence state directory
- `POUNCE_FEED_STALE_AFTER_HOURS`: stale warning threshold, default `6`
- `POUNCE_GITHUB_TOKEN`: optional token for GitHub advisory syncing
- `GITHUB_TOKEN`: fallback token name for GitHub advisory syncing
- `POUNCE_VULNERABILITY_ACTION`: default action for non-malware OSV/GHSA results, `warn` by default, `block` optional

## Runtime policy

Confirmed malicious intelligence:

- bundled seed IOC exact package matches
- GitHub malware advisories
- OSV `MAL-*` advisories

Default action: `block`

Warning-only intelligence by default:

- non-malware OSV or GHSA vulnerability results
- stale feed state
- verification gaps
- npm provenance gaps or provenance regression

Missing provenance is not treated as proof of malware, but it remains a meaningful warning signal.

## After syncing

1. Restart Codex.
2. Open the plugin directory in Codex.
3. Select the local marketplace and install or enable `Pounce`.
4. Use `pounce.vet` before dependency-affecting changes.
5. Ask Codex to show the Pounce dashboard when you want a chat-native status snapshot.

After source changes, rerun the installer and restart Codex so the local install picks up the updated files.

Use `--no-workspace-hooks` only if you explicitly want to skip the workspace enforcement layer.
