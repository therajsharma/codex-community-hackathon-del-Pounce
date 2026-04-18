# Pounce

Pounce is a local Codex plugin for dependency vetting, onboarding sweeps, and shell-time supply-chain guardrails.

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

## After syncing

1. Restart Codex.
2. Open the plugin directory in Codex.
3. Select the local marketplace and install or enable `Pounce`.
4. Use `pounce.vet` before dependency-affecting changes.

After source changes, rerun the installer and restart Codex so the local install picks up the updated files.

Use `--no-workspace-hooks` only if you explicitly want to skip the workspace enforcement layer.
