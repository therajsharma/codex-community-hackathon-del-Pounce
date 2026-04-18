# Pounce

Pounce is an agent-native dependency tripwire for Codex.

## One-line pitch

Pounce makes Codex safer to use in real repositories by vetting dependency changes before they are written or installed, scanning workspaces for known malicious package indicators, and blocking risky shell-time dependency commands.

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

## Current feature set

- Exact dependency release vetting for npm and PyPI
- IOC and suspicious artifact matching against bundled and synced intelligence
- Workspace sweep mode for malicious package indicators and install-time mechanisms
- Hook-based blocking for risky Bash dependency commands
- Managed workspace policy injection into `AGENTS.md`
- Local plugin install flow for Codex marketplace usage
- Feed sync and export workflow for normalized intelligence artifacts
- Local vet stamps for auditability

## Why it is a strong hackathon project

Pounce fits the Codex hackathon because it is both a developer tool and an agent workflow improvement:

- it is squarely in `Agentic Coding`
- it has a clear `Building Evals` angle because it scores and blocks dependency changes
- it is easy to demo live because the full loop happens inside Codex workflows

## Demo narrative

1. Show `pounce.vet` blocking a known malicious dependency.
2. Show a workspace sweep catching a known IOC.
3. Show the shell hook denying a risky dependency install.
4. Show the installer wiring Pounce into `AGENTS.md` and `.codex/hooks.json`.
5. Finish with the smoke script and test suite to prove the current feature set still works.

## Demo-ready status

For the hackathon presentation, the focus is demo reliability over broad product surface area:

- the metadata now points at a public repository instead of machine-local paths
- the README includes a fast demo path
- the repository includes a deterministic smoke script for the current feature set

## Next product step after the hackathon

The next major step is a stronger trust model for hosted feeds, including signed feed verification and more explicit source health reporting.
