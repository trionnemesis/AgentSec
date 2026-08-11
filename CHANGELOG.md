# Changelog

Notable changes, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[semantic versioning](https://semver.org). Status honesty matches
[`docs/roadmap.md`](docs/roadmap.md): integrations marked 🟡 there are first
drafts even when they appear in a release.

## [Unreleased]

### Added

- **`agentsec scan` says what the repository is before what is wrong with it.**
  The runtime framework fingerprint is composed into the `project` plane as
  `project.fingerprint`, so the CLI, the dashboard page and
  `agentsec://project/risks` read one classification: `confirmed`, `likely`,
  `configuration_only`, `not_detected` or `unsupported`, with the framework and
  its entrypoints named. Runtime agents and coding-agent configuration are
  carried as separate lists at every hop — a `.mcp.json` cannot become a claimed
  runtime agent by way of a template.
- The classification is reported **before** `agentsec init`, since whether there
  is an agent in a checkout does not depend on whether anyone wrote a manifest.

### Changed

- `PUBLISH_SCHEMA_VERSION` is `1.4.0`. `project.fingerprint` is a new optional
  key inside a plane that already existed; no plane was added or merged, and no
  published shape changed.
- The `project` plane is now projected field by field like every other published
  document rather than passed through whole. Its new content is derived from
  reading arbitrary repository files, so "the producer promises no source text"
  stopped being a guarantee that could live in one place.

### Fixed

- **Store schema migration runner** ([#44](https://github.com/trionnemesis/AgentSec/issues/44)).
  `SCHEMA_VERSION` moved from 1 to 2 when `run_counter` was added, but the
  stored version row was only ever written when absent — a database created
  under 1 reported version 1 forever, regardless of its actual tables. Opening
  a store now applies pending migrations in order and corrects the stored
  version; a version newer than this build supports raises `SchemaVersionError`
  rather than being silently opened.

## [0.2.0] — 2026-08-06

The release that gives AgentSec a first step. In 0.1.0 the entry point was
`agentsec run`, which could not be reached without a configured target — an
allowlist entry, a staging agent, usually a SIEM. An engineer who wanted to know
whether their repository was exposed had to finish someone else's sprint first.

`agentsec scan` needs a checkout and nothing else.

```
agentsec init → agentsec scan → agentsec scan --verify --target … → dashboard
```

### Added

- **Repository risk plane** (`agentsec init` / `agentsec scan`). Twelve
  deterministic rules read what a repository gives an AI agent — project
  instructions, subagent definitions, skills, hooks, pre-approved tool grants,
  MCP servers and memory stores — and rank what they find. Each risk resolves to
  `verified`, `verifiable` or `not_verifiable`; `scan --verify` hands the
  provable high-severity subset to the harness and returns real verdicts.
- **A risk is a reason to test, not a result.** `scan` exits `0` even with
  critical risks outstanding: nothing has executed and no detection control has
  been given the chance to fire. `not_verifiable` is the honest third state —
  neither a pass nor a failure, but AgentSec naming something it cannot settle.
- **The agent-configuration attack family** — four scenarios covering the
  surface the risk plane inventories: poisoned project instructions that
  exfiltrate a secret (`AGT-CONFIG-001`), a zero-width Unicode directive hidden
  in an agent definition (`AGT-CONFIG-002`), a hook interpolating untrusted
  content into a shell command (`AGT-CONFIG-003`), and an MCP server added
  mid-session with a credential-shaped env block (`AGT-CONFIG-004`). OWASP
  Agentic coverage goes 4/10 → 8/10.
- **Project resolution and surface discovery** — `.agentsec/project.yaml` gives
  a repository a stable id and reviewed relative locations, so which repository
  is a process-boundary decision rather than a tool argument.
- **Composed project dashboard**, served as one read-only resource
  (`agentsec://dashboard/latest`) and described by
  `schemas/project-dashboard.schema.json`: project identity, the risk plane, the
  four-axis purple rollup, Skill Assurance and static posture, each in its own
  property. Computed in memory — reading it starts no run and writes no file.
- **`agentsec://project/risks`** — the risk plane alone, for a client that wants
  the repository view without the run history. Takes no arguments at all.
- **Static posture ingestion** and finding-coverage correlation, plus run
  provenance recorded on every result.
- **Claude Desktop packaging** for the read-only report gateway.
- **Publication boundary**: published output is projected rather than filtered —
  each publisher names the fields it keeps, transcript turns become digests,
  principals and tenants become stable pseudonyms, and every projection carries a
  manifest of what it dropped. The report gateway declines to serve per-run
  evidence and the audit log at all, and refuses to start if a resource has no
  publication policy.
- **Project page** at <https://trionnemesis.github.io/AgentSec/>, and a
  Traditional Chinese edition of the README and the dashboard docs.
- `docs/feature-matrix.md` classifying every capability Core / Supporting /
  Experimental / Parked against the one path, and two ADRs: 0008 (Skill
  Assurance as a separate bounded context) and 0009 (the repository-first
  golden path, with four rejected alternatives and five accepted costs).

### Changed

- MCP resources 8 → 10 (7 published under `AGENTSEC_MCP_READ_ONLY=1`). The tool
  surface stays at 11: every capability added this cycle landed on
  `HarnessService` and reached the gateway as a resource, not a new verb.
- `PUBLISH_SCHEMA_VERSION` did not exist in 0.1.0 and ships here at 1.3.0,
  having moved three times within this cycle as the published surface grew.
  `repo_risk` is a required property on the composed dashboard, so a consumer
  validating strictly against an in-cycle version sees a new key; every shape
  already being read is untouched.
- `docs/roadmap.md` is sorted by layer rather than by completion status.
- The scenario validator warns on unspecific and empty detection assertions, and
  pre-flights span-only detection backends.

### Fixed

- `AGT-CONFIG-003` was tagged to a single hook path, so it correlated with this
  repository and with nothing in anyone else's. Retagged to the hook directory,
  which makes hook-injection risk `verifiable` in an arbitrary repository.
- Hook rules strip comments before matching. A comment *explaining* a proxied
  `curl` was being reported as network egress — a rule that reports the
  documentation of a risk as the risk teaches its reader to skip the plane.
- The guard hook's MCP argument check is scoped to AgentSec's own gateway rather
  than to every MCP call in the session.
- Twelve findings from the local deployment review, closed.

### Notes

Still alpha, and `docs/roadmap.md` still marks every row honestly: the Promptfoo
executor, the Wazuh/OTel HTTP collectors and the MCP server binding are written
but not yet proven against a live system. Two gaps this cycle's own risk plane
found in the catalogue are recorded rather than hidden — no scenario covers the
tool-grant/settings surface, and none covers the memory surface.

## [0.1.0] — 2026-07-29

Initial release.

### Added

- Scenario schema with the four-axis **Attack–Detection Contract**
  (prevention / detection / evidence / response) and four worked scenarios.
- Three-layer validator: JSON Schema → Pydantic → semantic rules.
- Deterministic purple evaluator with verdict precedence
  `error > detection_gap > prevention_gap > evidence_gap > response_gap > secure`
  — no language model in the decision path.
- Replay executor with fixture and HTTP adapters; promptfoo executor (first
  draft).
- Evidence collectors: Wazuh, OTel, tool audit, state diff (file backends
  tested; live backends first drafts).
- Policy guard: target allowlist with private-address enforcement, risk
  ceilings, quarantine, scoped single-use approval tokens.
- SQLite result store, finding workflow with enforced transitions.
- Reports: JUnit, self-contained HTML, normalised JSON; OWASP Agentic Top 10
  coverage reporting.
- MCP gateway with a contract-as-data tool surface and architectural tests.
- CLI with meaningful exit codes (`0` clean, `1` blocking, `2` could not tell)
  and a reusable CI gate workflow (`agentsec-gate.yml`).

[0.2.0]: https://github.com/trionnemesis/AgentSec/releases/tag/v0.2.0
[0.1.0]: https://github.com/trionnemesis/AgentSec/releases/tag/v0.1.0
