---
name: pounce
description: Vet dependency versions, run onboarding sweeps, and block compromised packages before install.
---

# Pounce

Use Pounce whenever a task adds, upgrades, installs, or recommends third-party dependencies.

## Primary workflow

Before making dependency-affecting changes, call `pounce.vet`.

Use `mode: "release"` for:
- package recommendations
- adding or upgrading a dependency
- checking install commands that mention an exact version

Use `mode: "sweep"` for:
- onboarding an existing repository
- incident response after a public package compromise
- checking a workspace for IOC strings or install-time execution mechanisms

Refresh the local intelligence feed when you need fresher malware data:
- `python3 plugins/pounce/scripts/pounce_feed.py sync`
- `python3 plugins/pounce/scripts/pounce_feed.py export --output /tmp/pounce-feed.json`

## Inputs

For release vetting, prefer:
- `ecosystem`
- `package_name`
- `version`
- `reason`
- `workspace` when you want a local vet stamp

Add `artifacts` when you already have suspicious strings, script snippets, or package metadata to inspect.

For repository sweeps, pass:
- `mode: "sweep"`
- `workspace`

## Operating rules

- Prefer exact versions. Do not recommend floating ranges when Pounce is in the loop.
- If `pounce.vet` returns `block`, do not write or install that dependency. Propose a safer exact version or no dependency.
- If `pounce.vet` returns `warn`, explain the warning and propose the safest exact alternative before proceeding.
- Confirmed malicious-package intelligence blocks by default. Warning-only vulnerability or provenance signals should be explained, not described as confirmed malware.
- If verification is unavailable, treat the result as a manual review gate rather than a green light.

## Response style

Turn findings into plain language:
- what matched
- why it matters
- what to do next

Keep the recommendation short and actionable.
