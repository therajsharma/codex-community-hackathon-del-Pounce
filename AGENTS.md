<!-- BEGIN POUNCE MANAGED BLOCK -->
## Pounce Policy

- Before proposing, writing, or running dependency-affecting changes, call `pounce.vet`.
- Treat `package.json`, lockfiles, `requirements*.txt`, `pyproject.toml`, `setup.py`, `setup.cfg`, `Pipfile`, `poetry.lock`, and install commands as dependency-affecting.
- Use `mode: "release"` for exact package/version checks and recommendation workflows.
- Use `mode: "sweep"` with the workspace path for onboarding or incident-response scans.
- If `pounce.vet` returns `block`, do not install or recommend that dependency. Propose a safer exact version or no dependency.
- If `pounce.vet` returns `warn`, explain the warning and prefer a safer exact version before proceeding.
- Prefer exact versions over floating ranges whenever Pounce is active.
<!-- END POUNCE MANAGED BLOCK -->
