# Pounce

Pounce is an agent-native dependency security layer for Codex.

## One-line pitch

Pounce makes Codex safer to use in real repositories by vetting dependency changes before they are written or installed, scanning workspaces for known malicious package indicators, blocking risky shell-time dependency commands, and surfacing workspace protection state in chat.

## Problem

AI coding agents make dependency changes faster than a human reviewer can reliably inspect them. That creates three practical failure modes:

1. a bad package version gets recommended or installed
2. a malicious indicator already exists in the workspace and goes unnoticed
3. a dependency file changes without a clearly vetted install flow

## Product

Pounce adds four layers of protection to the Codex workflow:

1. `pounce.vet` for exact release vetting and repository sweeps
2. shell-time command interception for dependency install commands
3. same-turn dependency guardrails that catch unexpected manifest or lockfile edits
4. refreshable threat-intelligence feeds with bundled fallback data

The visibility surface for that workflow is `pounce.dashboard`, which exposes workspace protection status, feed freshness and source selection, and recent verdicts.

Hosted feeds are bounded by an explicit transport policy: HTTPS only, redirects disabled, and a 5 MiB response cap. When verification is degraded, `pounce.vet` stays usable but marks the result for manual review while hook-enforced installs fail closed.

## Current feature set

- Exact dependency release vetting for npm and PyPI
- Suspicious artifact matching for strings such as install URLs or script snippets
- IOC and suspicious artifact matching against bundled and synced intelligence
- Workspace sweep mode for malicious package indicators and install-time mechanisms
- Hook-based blocking for risky Bash dependency commands
- Exact-version rewrite recommendations for non-exact install commands
- Same-turn allowlisting for vetted dependency mutations
- End-of-turn blocking when dependency files changed outside the vetted install path
- MCP dashboard snapshots rendered directly in chat
- Managed workspace policy injection into `AGENTS.md`
- Local plugin install flow for Codex marketplace usage
- Feed sync and export workflow for normalized intelligence artifacts
- Local vet stamps for auditability

## Implemented workflow

The current implementation uses three workspace hook events plus two MCP tools:

1. `UserPromptSubmit` snapshots dependency manifests and lockfiles into `.pounce/guard/turn-*.json`.
2. `PreToolUse` inspects Bash dependency commands and does one of three things:
   - blocks exact releases that match malicious intelligence
   - blocks non-exact specs and recommends a concrete exact rewrite
   - records the expected dependency mutation for vetted exact installs
3. `Stop` compares the end-of-turn dependency state against the saved snapshot and blocks unexplained manifest or lockfile edits.
4. `pounce.vet` performs release vetting, artifact inspection, or workspace sweep mode.
5. `pounce.dashboard` renders workspace protection status, feed status, and recent verdicts.

Supported shell command families today:

- `npm install`, `npm i`, `npm add`
- `pnpm add`, `pnpm up`, `pnpm dlx`
- `yarn add`, `yarn up`
- `bun add`
- `pip install`, `pip3 install`, `pipx run`
- `uv pip install`, `uv add`, `uvx`
- `poetry add`

Hook enforcement also fails closed for dependency commands hidden behind `sh`/`bash`/`zsh` `-c` wrappers, non-registry tarball/git/url/file sources, and piped execution paths.

Supported dependency files in the guard path:

- `package.json`
- `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`
- `requirements*.txt`
- `pyproject.toml`
- `setup.py`, `setup.cfg`
- `Pipfile`, `Pipfile.lock`
- `poetry.lock`
- `uv.lock`

Dashboard workspace protection states:

- `protected`: managed policy present, all three hook events configured, and `codex_hooks = true`
- `partial`: workspace resolved but setup is incomplete
- `unavailable`: no workspace could be resolved for dashboard inspection

Dashboard feed source selection values:

- `remote`
- `remote_cache`
- `local_sync_cache`
- `seed`

## Why it is a strong product fit

Pounce works well as both a developer tool and an agent workflow improvement:

- it sits directly in the agent workflow where dependency risk is created
- it provides a concrete evaluation surface because dependency changes can be scored and blocked
- it is easy to explain because the full loop happens inside Codex workflows

## Demo narrative

1. Show `pounce.vet` blocking known malicious npm and PyPI dependencies.
2. Show a workspace sweep catching a known IOC.
3. Show the shell hook denying a risky dependency install and forcing exact rewrites for floating specs.
4. Show the same-turn guard blocking unexplained dependency-file edits while allowing vetted same-turn installs.
5. Show the installer wiring Pounce into `AGENTS.md`, `.codex/hooks.json`, and `.codex/config.toml`.
6. Show `pounce.dashboard` in chat.
7. Finish with the smoke script and test suite to prove the current feature set still works.

## Current readiness

The current implementation prioritizes reliable end-to-end behavior over broad product surface area:

- the metadata now points at a public repository instead of machine-local paths
- the README includes a fast demo path
- the repository includes a deterministic smoke script for the current feature set
- the smoke script exercises release vetting, sweep mode, hook enforcement, same-turn guardrails, installer wiring, and MCP tool exposure

## Next product step

The next major step is a stronger trust model for hosted feeds, including signed feed verification and more explicit source health reporting.
