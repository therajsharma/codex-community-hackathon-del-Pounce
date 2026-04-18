# Getting Started with Pounce

Pounce adds dependency vetting, shell-time install guardrails, workspace sweeps, and chat-native protection visibility to Codex.

## Quick path

1. Install the local plugin into Codex.
2. Run the smoke demo.
3. Open the dashboard in Codex chat.
4. Run the test suite.

## Local install

From the repository root:

```bash
python3 plugins/pounce/scripts/install_local.py --workspace "$(pwd)"
```

## Smoke demo

Run the deterministic smoke check:

```bash
python3 plugins/pounce/scripts/pounce_demo.py
```

Optional JSON output:

```bash
python3 plugins/pounce/scripts/pounce_demo.py --json
```

## Use it in Codex

After installation, ask Codex:

```text
Show the Pounce dashboard for this workspace
```

The dashboard summarizes workspace protection, feed trust state, and recent vet or sweep results.

## Run verification

Run the test suite from the repository root:

```bash
pytest -q
```

## Optional feed refresh

If network access is available, refresh the local intelligence feeds:

```bash
python3 plugins/pounce/scripts/pounce_feed.py sync
```

## Limited-network behavior

Pounce keeps the core workflow usable even when feed refresh is skipped. The dashboard falls back through remote cache, local sync cache, and bundled seed data, while hosted feeds stay bounded to HTTPS, no redirects, and a 5 MiB response cap.
