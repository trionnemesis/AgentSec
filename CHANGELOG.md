# Changelog

Notable changes, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[semantic versioning](https://semver.org). Status honesty matches
[`docs/roadmap.md`](docs/roadmap.md): integrations marked 🟡 there are first
drafts even when they appear in a release.

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

[0.1.0]: https://github.com/trionnemesis/AgentSec/releases/tag/v0.1.0
