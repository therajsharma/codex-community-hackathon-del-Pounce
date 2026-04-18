# Hackathon Demo Runbook

This runbook is tuned for the Codex Community Hackathon in New Delhi on April 18, 2026.

The event is aimed at developers who are already comfortable shipping production-grade code, and the build directions include agentic coding and building evals. Pounce fits that framing well: it is a Codex-native security layer for dependency changes rather than a generic static scanner.

## What to emphasize

- Pounce is not just another dashboard.
- It lives in the path where agents actually make risky dependency changes.
- It gives Codex a security-aware dependency workflow with minimal friction.
- The dashboard is a Codex-native snapshot in chat, not a detached admin console.
- Non-exact install commands do not get a pass; Pounce forces an exact rewrite.
- The same-turn guard catches dependency file edits that bypass the vetted install path.

## Fast pitch

Pounce is a security tripwire for Codex. Before an agent adds or installs dependencies, Pounce can vet the exact release, block obviously risky shell installs, rewrite non-exact commands into exact ones, sweep a workspace for known malicious indicators, and leave a local audit trail so the dependency story is explainable.

## Five-minute demo flow

1. Start with the problem:
   "AI agents move faster than human dependency review."
2. Run the smoke demo:
   `python3 plugins/pounce/scripts/pounce_demo.py`
3. Point out what the smoke script actually covers:
   - malicious npm release blocked
   - malicious PyPI release blocked
   - workspace IOC found
   - shell install denied
   - dependency guard blocks unexplained manifest edits
   - dependency guard allows vetted same-turn edits
   - installer wires policy and hooks
   - MCP exposes `pounce.vet` and `pounce.dashboard`
4. Ask Codex to show the Pounce dashboard for this workspace.
5. Show the plugin metadata and README for polish.
6. End with the test suite:
   `pytest -q`

## Commands to use

Install locally into Codex:

```bash
python3 plugins/pounce/scripts/install_local.py --workspace "$(pwd)"
```

Run the hackathon smoke check:

```bash
python3 plugins/pounce/scripts/pounce_demo.py
```

Optional JSON form if you want a structured result on screen or in a recording:

```bash
python3 plugins/pounce/scripts/pounce_demo.py --json
```

Then in Codex chat:

```text
Show the Pounce dashboard for this workspace
```

Run the full automated test suite:

```bash
pytest -q
```

Optional: refresh intelligence feeds before the presentation if network is available:

```bash
python3 plugins/pounce/scripts/pounce_feed.py sync
```

## Fallback plan if network is unreliable

The demo path is intentionally deterministic and relies on bundled threat intelligence where possible. That means you can still show the core value even if live feed refresh is skipped. The dashboard will also fall back through remote cache, local sync cache, and finally seed data.

## What judges should remember

- Pounce makes Codex safer without forcing developers out of their normal workflow.
- The current feature set is demoable end to end on a laptop.
- The implementation is broader than a point scanner: release vetting, hook enforcement, same-turn guardrails, and a dashboard all work together.
- The project already has a clean next step after the hackathon: stronger feed trust and distribution hardening.
