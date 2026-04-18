# Pounce

Pounce is a local Codex plugin for dependency vetting, onboarding sweeps, shell-time supply-chain guardrails, and near-real-time malicious-package intelligence.

## Local install

From the repository root:

```bash
python3 plugins/pounce/scripts/install_local.py --workspace /Users/sysuser/Documents/codebase/security/proj-zero
```

This does four things:

1. syncs the source plugin to `~/.codex/plugins/pounce`
2. creates or updates `~/.agents/plugins/marketplace.json`
3. injects the managed Pounce block into the workspace `AGENTS.md`
4. writes or updates workspace `.codex/hooks.json` and `.codex/config.toml` so shell-time vetting does not depend on bundled plugin hooks

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

After source changes, rerun the installer and restart Codex so the local install picks up the updated files.

Use `--no-workspace-hooks` only if you explicitly want to skip the workspace enforcement layer.
