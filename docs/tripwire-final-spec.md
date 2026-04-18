# Tripwire

## Final product doc

Version: 2026-04-17

This document captures the current definition of **Tripwire**, the supply-chain security product we discussed for the Codex hackathon. It is a product brief plus an implementation plan. The goal is to preserve the full direction before coding the full solution.

## 0. Product statement

Tripwire is a Codex-native security layer that blocks compromised packages at the moment an AI coding agent tries to add or install them.

It ships as one installable Codex plugin that bundles a skill, hooks, and an MCP server, uses three detection moments — onboarding sweep, suggestion-time vet, and install-time hook guard — and is explicitly designed to stop the March-April 2026 LiteLLM and Axios attack patterns with near-zero configuration.

## 1. Problem statement

In March and April 2026, multiple high-profile supply-chain incidents showed that developers cannot rely on package reputation alone.

Recent examples that directly shaped this idea:

- **LiteLLM compromise**: compromised PyPI releases `1.82.7` and `1.82.8`
- **Axios compromise**: malicious publish path that introduced `plain-crypto-js@4.2.1`
- IOC examples from the incident set:
  - `plain-crypto-js@4.2.1`
  - `sfrclak.com`
  - `litellm_init.pth`
  - install-time Python code using `subprocess.Popen`

The core lesson is:

> The risk is not only “is this library good?” but “should this exact release be trusted right now?”

This is more relevant in AI-assisted and vibe-coded projects, where agents and developers may add dependencies quickly, use broad semver ranges, and optimize for velocity over review depth.

## 2. Product thesis

Tripwire is a **release-risk intelligence layer for AI-assisted coding**.

It sits between:

- a user asking Codex to scaffold or extend a project
- Codex proposing or writing dependency changes
- the actual install or write operation

Tripwire decides whether the dependency change should be:

- `allow`
- `warn`
- `block`

Tripwire is not a generic dashboard and not only a package reputation tool. It is designed to make decisions at the level of:

- exact package version
- install-time behavior
- IOC matches
- release freshness
- provenance and publishing trust
- workspace exposure state

## 3. Primary users

### Primary user

- developers building greenfield projects with Codex or similar agentic coding tools

### Secondary users

- teams that want security guardrails around AI-generated dependency changes
- maintainers who want quick infection triage after a public incident
- evaluators building safety controls for agentic coding workflows

## 4. Product shape

Tripwire is one product with **three primary operating modes**.

### A. Preventive Guardrail

Purpose:
- stop risky dependency additions before they land

Core behavior:
- intercept dependency-related prompts or tool actions
- call `tripwire.vet`
- evaluate the exact release
- block or rewrite to a safer exact version

Best fit:
- greenfield coding
- Codex-first workflows
- dependency additions during scaffolding and feature work

### B. Infection Triage Agent

Purpose:
- determine whether the current repo, build pipeline, or workspace was exposed to a known incident

Core behavior:
- scan files, lockfiles, workflows, logs, and artifact strings
- match known IOC signatures
- determine likely exposure window
- propose remediation and credential rotation scope

Best fit:
- response after a public package compromise
- repo onboarding
- security audit sweeps

### C. Threat-Aware Dependency Recommender

Purpose:
- help a user choose safer packages and safer exact versions before adoption

Core behavior:
- compare candidate libraries
- prefer packages with better trust signals
- recommend exact versions, not just package names
- recommend no dependency where possible

Best fit:
- greenfield architecture decisions
- rapid prototyping
- AI-generated dependency suggestions

## 5. Additional variants and extensions

These are valid extensions in the same product domain.

### Release Diff Explainer

- explain what changed between the last trusted release and the proposed one
- highlight new install scripts, transitive dependencies, or suspicious manifest changes

### Install Sandbox

- install the package in an instrumented sandbox
- observe filesystem writes, process launches, and network calls

### Dependency Quarantine Proxy

- place a controlled delay on newly published releases
- quarantine fresh releases until they pass policy or human review

### Lockfile Doctor

- find floating ranges, risky upgrades, weak pinning, and suspicious transitive churn

### PR / CI Policy Bot

- comment on dependency-related pull requests
- enforce checks in CI before merge

### Maintainer Trust View

- summarize trust and maintenance signals for candidate packages

### Secret Blast Radius Mapper

- show which secrets, files, or environments would have been reachable if a malicious install ran

### Dependency Minimizer

- determine whether a new dependency is necessary at all

### Incident Watchlist

- continuously monitor packages already used by the workspace

### Agent Policy Pack

- provide a hardened ruleset for coding agents

## 6. Hackathon framing

Tripwire is well aligned with these Codex hackathon build directions:

- **Agentic Coding**
- **Domain Agents**
- **Building Evals**

Why it fits:

- Codex becomes part of the product, not only the development tool
- the solution is highly demoable
- the product has a clear human pain point
- the idea can show measurable value through evals

### Why this instead of existing tools

The likely comparison set is tools like Snyk, Socket, or StepSecurity.

Tripwire's answer is:

- those tools are generally built for enterprise security teams, CI/CD pipelines, or after-the-fact review
- Tripwire is for the solo or small-team vibe coder using an AI coding agent directly
- Tripwire installs as a Codex plugin and operates **inside the agent loop**
- the key behavior is not "show a dashboard later" but "block or warn at the moment the agent proposes the bad package"

## 6A. Codex-native advantages

Tripwire should lean into the newest Codex product direction rather than pretending to be a generic security scanner.

### Plugin-first distribution

Tripwire should be packaged primarily as a **Codex plugin**.

Why:

- plugins are the install and discovery unit
- the plugin can bundle the Tripwire skill, the MCP config, and the hook config together
- this gives a cleaner story than asking users to assemble separate pieces manually

### Native tool call via MCP

Tripwire exposes `tripwire.vet` through MCP, which means Codex can call it as a first-class structured tool instead of relying on prompt-only conventions.

### Native hook enforcement

Hooks let Tripwire intervene exactly where it matters:

- before dependency-related prompts turn into actions
- before tool calls write dependency-affecting files
- before suspicious install commands proceed

### Automations

Codex automations are a natural stretch for Tripwire. After the core plugin works, the same system can support:

- scheduled watchlist scans
- daily dependency hygiene checks
- recurring onboarding sweeps for active repos

### Memory-backed policy

If memory is available in the user’s Codex setup, Tripwire can persist:

- approved registries
- blocked packages
- cooldown windows
- team or workspace-specific allowlists

### Parallel security checks

Codex-native parallelism is a product advantage, not only an implementation detail.

Tripwire can run:

- tag-match validation
- provenance checks
- dependency diff checks
- IOC scans

at the same time and then merge the verdict into one explanation.

### Optional plugin extensions later

Future plugin extensions can add:

- GitHub pull request review for dependency changes
- browser or computer-use evidence collection for suspicious registry pages or release trails

These are stretch extensions, not MVP requirements.

## 7. Product principles

### Principle 1: exact release over general reputation

The system should evaluate:

- package name
- exact version
- artifact strings
- release timing
- install-time behavior

### Principle 2: prevention over passive alerting

The strongest experience is blocking or redirecting a bad dependency before install.

### Principle 3: AI-native integration

Tripwire must plug into the agent workflow directly, not sit beside it as a separate tab nobody checks.

### Principle 4: explainability

A verdict must include a plain-language reason.

### Principle 5: low-friction distribution

Setup should be close to:

1. install the plugin
2. enable it in the workspace
3. start using Tripwire with no separate setup flow in the common path

### Principle 6: mechanism-level detection is the most future-proof signal

The universal detector is install-time execution:

- npm `postinstall` / `prepare` paths
- Python `.pth` injection
- install-time bootstrap code that launches processes or reaches the network

This matters because it catches future zero-days even when there is no CVE or public IOC yet. In the 2026 incidents, the delivery mechanisms were the real invariant.

## 8. Core workflows

### Workflow 1: greenfield scaffold protection

1. user asks Codex to build a project
2. Codex proposes dependencies
3. before dependency-related files are written, Tripwire runs
4. `tripwire.vet` checks the exact release or candidate package
5. Tripwire returns:
   - `allow`
   - `warn`
   - `block`
6. if needed, Codex rewrites the dependency choice

### Workflow 2: onboarding sweep

1. user enables Tripwire in an existing repo
2. Tripwire performs an initial IOC-aware scan
3. known exploit signatures and live IOC feed indicators are checked
4. Tripwire returns a short exposure report and remediation next steps

### Workflow 3: package choice

1. user asks for a package recommendation
2. Codex calls `tripwire.vet` or the recommendation flow
3. Tripwire evaluates trust and risk signals
4. Codex recommends the safest viable option with a pinned version

### Workflow 4: incident response

1. a public package compromise is reported
2. user asks whether a repo is exposed
3. Tripwire scans lockfiles, install commands, workflows, and suspicious artifacts
4. Tripwire identifies exposure status and suggests remediation

## 9. Technical concept

Tripwire has six core pieces.

### 9.1 Plugin distribution layer

A Codex plugin is the primary distribution wedge.

Reason:
- plugins are the cleanest Codex-native install unit
- the plugin can bundle skills, hooks, and MCP configuration together
- this is the strongest fit for a Codex-focused hackathon

### 9.2 Bundled skill layer

The plugin should include a Tripwire skill.

Reason:

- the skill provides the workflow guidance
- the plugin provides the installation and runtime bundle

### 9.3 Local plugin runtime

The installed plugin runtime should contain:

- plugin manifest
- hooks config
- MCP server config
- helper scripts
- seeded IOC data

### 9.4 MCP server

Tripwire exposes a specific tool via the Model Context Protocol:

- `tripwire.vet`

This tool is the main structured interface for Codex to call before dependency-related changes.

### 9.5 Hooks

Hooks provide guardrails around prompts and tool usage.

Hook use cases:

- detect dependency-related prompts
- detect dependency-related file writes
- block known bad signatures
- remind the agent to call `tripwire.vet`

### 9.6 Workspace policy

The workspace gets a managed `AGENTS.md` policy block that instructs Codex to call `tripwire.vet` before dependency-resolution changes.

Important note:

- for Codex, the correct filename is **`AGENTS.md`**
- not `agent.md`

## 10. Distribution and installation model

This is the current intended installation model.

### Preferred path: installable Codex plugin

Tripwire should be published primarily as a Codex plugin bundle.

The plugin should contain:

- `.codex-plugin/plugin.json`
- `skills/tripwire/SKILL.md`
- `hooks.json`
- `.mcp.json`
- local helper scripts
- seeded IOC data

This is the preferred hackathon story:

1. install one plugin
2. restart Codex if needed
3. open a workspace
4. Tripwire is available as a native Codex capability

### Fallback path: skill + bootstrap

If plugin packaging or install UX is incomplete during the hackathon, keep a fallback development path:

1. install the Tripwire skill
2. run bootstrap
3. generate the plugin runtime locally

That fallback path should not be the headline story unless the plugin install path is not ready.

### Generated local runtime files

- `~/plugins/tripwire/.codex-plugin/plugin.json`
- `~/plugins/tripwire/hooks.json`
- `~/plugins/tripwire/.mcp.json`
- `~/plugins/tripwire/scripts/*`
- `~/plugins/tripwire/data/seed_iocs.json`
- `~/.agents/plugins/marketplace.json`
- `<workspace>/AGENTS.md`

This shape was chosen because:

- the plugin is now the primary install unit
- the skill remains useful as a bundled workflow and fallback entrypoint
- hooks and MCP registration still require coherent local runtime files

### Bootstrap sequence

The bootstrap order should be:

1. plugin assets or fallback skill assets are available locally
2. the user or Codex invokes Tripwire in a workspace
3. if the plugin runtime is not already present, bootstrap runs
4. bootstrap writes or refreshes the local plugin runtime files
5. bootstrap updates `~/.agents/plugins/marketplace.json` if needed
6. bootstrap injects or updates the managed Tripwire block in `<workspace>/AGENTS.md`
7. the user is told to restart Codex if a newly installed plugin must be reloaded

### Idempotency and `AGENTS.md` policy

Bootstrap must be idempotent.

Requirements:

- re-running bootstrap must not duplicate plugin entries in `marketplace.json`
- re-running bootstrap must not duplicate the managed Tripwire block in `AGENTS.md`
- if `AGENTS.md` already exists, preserve user-written content and replace only the managed Tripwire block
- if generated files already exist, overwrite them intentionally rather than append or fork them silently

## 11. Planned file generation

### Required repo-side source files

- `.codex-plugin/plugin.json`
- `skills/tripwire/SKILL.md`
- `hooks.json`
- `.mcp.json`
- templates for generated runtime files
- bootstrap script
- seeded IOC reference data

### Required generated local files

#### `SKILL.md`

Purpose:
- trigger and explain the Tripwire workflow

Location:
- bundled inside the plugin at `skills/tripwire/SKILL.md`
- optionally installed into `~/.codex/skills/tripwire/SKILL.md` for the fallback path

#### `hooks.json`

Purpose:
- intercept relevant prompts and tool calls
- block direct known-bad signatures
- remind the agent to call `tripwire.vet`

Location:
- canonical source in the plugin bundle
- generated at `~/plugins/tripwire/hooks.json` in the fallback bootstrap path

#### `AGENTS.md`

Purpose:
- define workspace policy for Codex
- require `tripwire.vet` before dependency-affecting changes

Location:
- generated or updated at `<workspace>/AGENTS.md`

#### plugin manifest

Purpose:
- declare Tripwire as a local plugin with hooks and MCP references

Location:
- canonical source in the plugin bundle
- generated at `~/plugins/tripwire/.codex-plugin/plugin.json` in the fallback bootstrap path

#### `.mcp.json`

Purpose:
- register the local MCP server exposing `tripwire.vet`

Location:
- canonical source in the plugin bundle
- generated at `~/plugins/tripwire/.mcp.json` in the fallback bootstrap path

## 12. Exact IOC and exploit signatures to seed

The first seed set should explicitly include the incident artifacts we discussed.

### Axios-related

- `plain-crypto-js@4.2.1`
- `sfrclak.com`

### LiteLLM-related

- `litellm` `1.82.7`
- `litellm` `1.82.8`
- `litellm_init.pth`
- `subprocess.Popen` when seen in install-time Python bootstrap logic

## 13. Live IOC feed

Tripwire should support a live IOC feed for onboarding sweeps and future incidents.

### Feed purpose

- keep Tripwire current after the plugin is installed
- avoid shipping only a static signature list
- let the same runtime catch new public incidents quickly

### Feed format

Accept either:

- JSON object with `items`
- JSON array
- NDJSON

Each item should include fields like:

- `id`
- `severity`
- `reason`
- `match`

### Feed use

- loaded by the MCP server
- loaded by the hooks
- merged with local seed IOC data

### Fetch and cache policy

For the hackathon build, the feed should be fetched on first use and cached in memory with a short TTL.

Chosen behavior:

- fetch on first call
- cache for 10 minutes
- if refresh fails, continue using the last good cached copy
- if there is no cached copy, fall back to the local seeded IOC set

## 14. `tripwire.vet` tool contract

Initial intended responsibilities:

- vet an exact package release
- vet arbitrary artifact strings against IOC rules
- perform onboarding sweeps
- write a workspace-local vet stamp

### Proposed inputs

- `mode`: `release` or `sweep`
- `ecosystem`: `npm`, `pypi`, or `mixed`
- `package_name`
- `version`
- `artifacts`
- `ioc_query`
- `workspace`
- `reason`

### Proposed outputs

- `verdict`
- `summary`
- `findings`
- `checked_at`
- `stamp_path`

### Possible verdicts

- `allow`
- `warn`
- `block`

### `findings` schema

`findings` must be structured, not free text. Each finding should be shaped like:

```json
{
  "signal_id": "ioc-2026-031",
  "signal_name": "exact_ioc_match",
  "category": "ioc",
  "severity": "critical",
  "verdict_impact": "block",
  "evidence": "Matched plain-crypto-js@4.2.1 from the March 31, 2026 Axios compromise",
  "source": "seed_ioc|live_ioc|registry|github|package_diff|install_scan",
  "artifact": "plain-crypto-js@4.2.1"
}
```

Required fields:

- `signal_id`
- `signal_name`
- `category`
- `severity`
- `verdict_impact`
- `evidence`
- `source`
- `artifact`

This schema is what makes the explainability principle real: Codex can turn each finding directly into a user-facing sentence.

### Threshold logic

Initial verdict rules:

- any exact IOC match => `block`
- any mechanism-level execution hit with strong evidence (`postinstall`, `.pth`, or install-time code execution tied to the candidate package) => `block`
- GitHub tag mismatch => `warn`
- missing npm SLSA provenance => `warn`
- release age below 72 hours => `warn`
- new never-before-seen transitive dependency in the candidate version diff => `warn`
- two or more independent `warn` signals together => escalate to `block`

This is intentionally simple. The hackathon version does not need a scoring model.

### Failure behavior

Tripwire should fail to `warn`, not fail open and not fail hard closed.

If npm, PyPI, GitHub, or the live IOC feed cannot be reached:

- return `verdict: warn`
- include a finding such as `verification_unavailable`
- state that the package could not be fully verified and should be checked manually

This is the safest demo-time behavior on unreliable conference Wi-Fi.

## 15. Initial heuristics and decision signals

Beyond direct IOC matching, Tripwire should evolve to support:

- **GitHub tag-match check**
  - compare the package version on the registry against the upstream GitHub tags or releases
  - if a registry artifact exists with no corresponding source tag or release, flag it
  - this is the concrete signal that would have caught the March 2026 LiteLLM compromise

- **npm SLSA provenance check**
  - query npm for provenance on the exact package version
  - if the previous trusted version had provenance and the new version does not, flag it
  - this is the concrete provenance signal that would have caught the Axios 1.14.1 publish path

- **new transitive dependency diff**
  - compare the proposed version's dependency set against the currently installed or last-known-good version
  - flag packages that appear for the first time, especially in patch releases
  - this is the anomaly detector that would have highlighted `plain-crypto-js`

- **install-time mechanism scanner**
  - scan for `postinstall`, `prepare`, `.pth`, or install-time bootstrap code
  - treat this as the most important future-proof detector because it can catch new attacks with no CVE and no public IOC yet

- release age / cooldown checks
- unusual manifest drift between patch versions
- mismatch from normal publisher or release pattern
- suspicious domains or network indicators
- broad semver ranges that may resolve to a risky fresh release

## 16. MVP definition

The best MVP for the hackathon is:

1. one product
2. three modes
3. one core tool (`tripwire.vet`)
4. IOC-aware guardrails
5. a short, clean demo

### MVP scope

- npm + PyPI only
- cover the major March-April 2026 attack patterns:
  - maintainer account compromise
  - CI/CD token theft via a compromised scanner or build path
  - `postinstall` hook injection
  - Python `.pth` file injection
- seeded IOC set based on the 2026 LiteLLM and Axios incidents
- live IOC feed support
- `tripwire.vet`
- hooks for prompt/tool interception
- workspace `AGENTS.md` policy injection
- one onboarding sweep flow
- one package recommendation flow
- one blocking demo case

### Cut list if time runs out

Cut in this order:

1. live IOC feed auto-refresh; ship the March-April 2026 IOC set as a static seed
2. secondary ecosystem managers beyond the core npm and PyPI path, such as `pnpm`, `yarn`, and `poetry`
3. extra integration polish beyond the core `tripwire.vet` + hook-guard flow

Do **not** cut:

- blocking the LiteLLM-style tag-mismatch path
- blocking the Axios-style provenance / transitive anomaly path

## 17. Stretch scope

- release diff explainer
- install sandbox
- dependency quarantine mode
- lockfile doctor
- CI / PR bot
- richer reputation and provenance scoring
- secret blast radius mapping

## 18. Demo plan

The strongest demo sequence is:

1. start with a clean repo and a clean audit result to build trust
2. ask Codex to scaffold an app or recommend a safe package
3. show a normal green-path Tripwire result first
4. manually run the dramatic bad case, for example `npm install axios@1.14.1`
5. show a red Tripwire response that names the specific IOC, the specific package, and the specific incident date
6. show the second headline detection moment:
   - LiteLLM-style GitHub tag mismatch, or
   - Axios-style missing provenance plus new transitive dependency
7. close with the line:
   - "Two of the biggest supply chain attacks of the last 30 days. Zero config. One plugin."

### Demo beats to rehearse

- open with a visible green checkmark on a clean audit
- make the bad install command feel deliberate and manual
- ensure the red output names a stable signal ID and the incident date, for example:
  - `block: ioc-2026-031, Axios supply chain compromise, March 31, 2026`
- keep the explanation short enough that the judges can retell it after the demo

## 19. Evals

Tripwire should include a small eval set.

### Eval goals

- catch the seeded incident cases
- avoid blocking clearly safe cases too often
- explain verdicts cleanly

### Example eval buckets

- known bad incident versions
- safe neighboring versions
- packages with legitimate install scripts
- benign repos with no IOC matches
- suspicious artifact text snippets

## 20. Non-goals for v1

- full enterprise SCA replacement
- full malware sandboxing platform
- universal ecosystem coverage
- perfect provenance analysis across all registries
- continuous background monitoring for every possible artifact type

## 21. Open questions

- how strict should default blocking be for fresh releases with no direct IOC hit?
- should recommendation mode and vet mode be separate tools or one tool with multiple modes?
- how much install-time sandboxing is feasible in the hackathon timeframe?
- what external IOC source should back the live feed in the hackathon prototype?

## 22. Current implementation direction

If this is built as discussed, the recommended first cut is:

- installable Codex plugin as the primary distribution unit
- bundled Tripwire skill inside the plugin
- one bootstrap or refresh path as fallback and development support
- generated workspace `AGENTS.md` policy
- MCP tool: `tripwire.vet`
- hook-based reminders and direct IOC blocking
- exact exploit signature seeds from the March-April 2026 incidents
- Codex only for the hackathon build; the architecture may generalize later, but that is not part of the claim

### Team split for a two-person build

Suggested ownership split:

- **Detection engine owner**
  - pure Python
  - no Codex-specific assumptions
  - package metadata fetchers
  - IOC matching
  - tag-match check
  - SLSA provenance check
  - transitive-diff logic
  - verdict generation

- **Codex integration owner**
  - `SKILL.md`
  - `hooks.json`
  - MCP server and `tripwire.vet`
  - `AGENTS.md` injection
  - plugin packaging
  - bootstrap flow
  - demo harness and narration

### Operating constraints

- `tripwire.vet` should return in under 2 seconds for a single package check
- an install command involving around 20 packages should complete Tripwire analysis in under 10 seconds
- cache registry, GitHub, and IOC feed responses aggressively enough to stay inside that envelope

### Privacy and telemetry stance

Tripwire should be local-first.

Allowed outbound traffic:

- npm registry
- PyPI
- GitHub
- user-configured IOC feed

Disallowed by default:

- product telemetry
- phoning home to a Tripwire-owned backend
- sending workspace contents anywhere other than the registries and feed needed for verification

## 23. References used in the discussion

- PyPI incident report on the LiteLLM / Telnyx supply-chain incident
- LiteLLM security notice for the March 2026 compromise
- Microsoft write-up on the Axios compromise
- OpenAI write-up on the Axios developer tool compromise

These references shaped the product direction, especially the emphasis on:

- exact release trust
- malicious install-time behavior
- live incident intelligence
- cooldown and guardrail-based prevention
