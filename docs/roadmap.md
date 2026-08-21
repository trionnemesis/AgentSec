# Roadmap

Sorted by **Core / Adoption / Experimental**, not by completion status
([#32](https://github.com/trionnemesis/AgentSec/issues/32)). Which layer
something belongs to is the durable fact; whether it is finished changes weekly,
and a roadmap sorted by the second answers no planning question.

Status marks: ✅ has tests · 🟡 written, never run against a live system · 🔲 not built.

See [`feature-matrix.md`](feature-matrix.md) for the classification of every
capability and for the known gaps on the golden path.

---

## Core — the golden path

```
agentsec init → agentsec scan → agentsec scan --verify -t <id> → dashboard
```

| Component | Status | Notes |
|---|---|---|
| Scenario schema + Attack–Detection Contract | ✅ | `schemas/scenario.schema.json`, 8 worked examples |
| Three-layer validator | ✅ | JSON Schema → Pydantic → 15 semantic rules |
| Purple evaluator, four axes | ✅ | pure function; ~60 tests |
| Verdict precedence | ✅ | `error > detection_gap > prevention_gap > evidence_gap > response_gap > secure` |
| Target allowlist + private-address guard | ✅ | `production` not expressible; public hosts refused |
| Policy guard (risk ceiling, quarantine, approvals) | ✅ | single decision point for CLI, MCP and CI |
| Approval tokens (scoped, expiring, single-use) | ✅ | CLI-only; no MCP tool grants them |
| Replay executor + fixture/HTTP adapters | ✅ | deterministic; the one CI should rely on |
| Evidence collectors: Wazuh, OTel, tool audit, state diff | ✅ | file backends tested; timeline rebasing for fixtures |
| Run provenance (`recorded` / `live` / `mixed`) | ✅ | a fixture-derived `secure` is labelled as such ([#27](https://github.com/trionnemesis/AgentSec/issues/27)) |
| SQLite store (runs, findings, audit log) | ✅ | latest-run-per-scenario aggregates |
| Store schema migration runner | ✅ | ordered, idempotent, fails closed on an unrecognised future version ([#44](https://github.com/trionnemesis/AgentSec/issues/44)) |
| CLI with meaningful exit codes | ✅ | `0` clean, `1` blocking, `2` could not tell |
| Selected-project manifest and discovery | ✅ | `.agentsec/project.yaml`; relative locations only, traversal and symlink escape refused |
| Runtime framework fingerprint engine | ✅ | deterministic, read-only detection for LangGraph/LangChain, OpenAI Agents SDK, AutoGen, Semantic Kernel, CrewAI and framework-neutral tool calling; development-agent config stays separate |
| Fingerprint composed into `scan`, dashboard and MCP resource | ✅ | `project.fingerprint`; reported even before `agentsec init`, and `not_detected` never renders as a pass ([#32](https://github.com/trionnemesis/AgentSec/issues/32)) |
| Tool-grant and memory surfaces | ✅ | one entry per permission rule; `.claude/memory` declared like any other surface ([#32](https://github.com/trionnemesis/AgentSec/issues/32)) |
| **Repository risk plane** (`agentsec scan`) | ✅ | 12 deterministic rules across agents, skills, hooks, tool grants, MCP and memory ([ADR 0009](adr/0009-repository-first-golden-path.md)) |
| **Risk → scenario triage** | ✅ | `verified` / `verifiable` / `not_verifiable`; `scan --verify` drains the queue |
| `config-surface:` correlation, shared | ✅ | `scenario/surface_tags.py`; the risk and posture planes cannot disagree |
| `AGT-CONFIG-*` agent-configuration family | ✅ | 4 scenarios ([#26](https://github.com/trionnemesis/AgentSec/issues/26)); `gate: warning` until stable across nightlies |
| Publication projection + fail-closed publication | ✅ | unknown output kind raises; a resource with no policy stops the gateway booting |
| Versioned dashboard contracts | ✅ | `dashboard.schema.json`, `project-dashboard.schema.json`; validated on every read |

### Core — open

- [ ] **Run against one real staging agent end to end**, and fix what that
      reveals. Still the single most valuable open item.
- [ ] **A scenario covering the tool-grant / settings surface.**
      `ASI-TOOL-PERMISSION-BYPASS` fires at `critical` and reports
      `not_verifiable`, because nothing is tagged at `.claude/settings.json`.
      The highest-value gap the risk plane exposed.
- [ ] **Tag `AGT-XPIA-001` at a memory surface**, so
      `ASI-MEMORY-UNREVIEWED-STORE` becomes verifiable.
- [ ] Fixture recordings and a Wazuh rule pack for `AGT-CONFIG-001..004`
      (`100901`–`100904`). Until recorded, the family is scoped to
      `environments: [ci, staging]` and `scan --verify` needs a real target.
- [ ] Wazuh rule pack for the four original bundled scenarios
      (`100501`, `100610`, `100720`, `100810`)

---

## Adoption — making the path usable by a team

| Component | Status | Notes |
|---|---|---|
| Finding workflow with enforced transitions | ✅ | cannot verify a detection gap without a detection rule |
| Report normaliser → JUnit / HTML / JSON | ✅ | HTML is self-contained and theme-aware |
| OWASP Agentic Top 10 coverage reporting | ✅ | 8/10 categories covered by the bundled scenarios |
| MCP contract as data + architectural tests | ✅ | forbidden tool/param names fail the build |
| Composed dashboard resource | ✅ | `agentsec://dashboard/latest`, five planes kept separate |
| Repository risk resource | ✅ | `agentsec://project/risks`, read-only, takes no arguments |
| Dashboard page / Live Artifact source | ✅ | `agentsec dashboard --html` renders the same template a hosted Artifact does |
| Claude Desktop / Cowork packaging | ✅ | `packaging/claude-desktop/` |
| Resource allowlist for the report gateway | ✅ | evidence, audit and target authoring detail are unregistered under `AGENTSEC_MCP_READ_ONLY=1` |
| MCP server (FastMCP binding) | 🟡 | a real stdio client drives a spawned server in CI; no other client has connected |

### Adoption — open

- [ ] **Host the Artifact.** The page and the resource exist; publishing it and
      binding it to a Desktop-registered gateway is manual. Checklist in
      `packaging/claude-desktop/README.md` — three of seven steps are asserted by
      `tests/test_packaging.py`, four need a person.
- [ ] **Dual README paths**: "engineer quick start" (scan-first) and
      "security/platform setup" (targets, scenarios, Wazuh/OTel mappings).
- [ ] **Simplified default output.** Engineer-facing finding states are
      `open → fixing → verified`; the full transition table stays expert mode.
- [ ] Read-only remote gateway with OAuth (deployment option C). The gateway half
      is built; authentication — OAuth/OIDC, RBAC, TLS termination — is not.
- [ ] A promptfoo custom provider that resolves `target_id` server-side.
- [ ] GitHub PR summary: merge decision, blocking findings, untested scope,
      evidence link.

---

## Experimental — written, unproven

Do not treat these as production-ready. The deterministic core is; these are
first drafts.

| Component | Status | What is missing |
|---|---|---|
| Promptfoo executor | 🟡 | config generation and output parsing written; needs a real agent |
| Wazuh OpenSearch collector | 🟡 | query shape written against the `wazuh-alerts-*` mapping; untested live |
| OTel HTTP collector | 🟡 | Tempo-style search API; untested live |
| HTTP target adapter | 🟡 | assumes `{"reply": ...}`; real agents need per-target shims |
| Static posture ingestion | ✅ | opt-in; requires a third-party report, `not_tested` when absent ([#25](https://github.com/trionnemesis/AgentSec/issues/25)) |

---

## Parked

Frozen until the golden path has adoption evidence. Parking is not rejection; it
is declining to widen the surface while the middle is unproven.

| Component | Why parked |
|---|---|
| Skill Assurance (`skill_eval`) | Separate schema, runner, store, CLI and workflow — the standard indicators of a separate repository ([ADR 0008](adr/0008-skill-assurance-bounded-context.md), [#14](https://github.com/trionnemesis/AgentSec/issues/14)). The plane reports `not_tested` honestly today. |
| PyRIT executor | A third executor before one live path works buys nothing |
| pytest executor | Same |
| MITRE ATLAS coverage | A second taxonomy over the same eight scenarios |
| Multi-agent scenarios (`AAI005`) | Needs per-agent step targeting |
| Cost/latency budgets as a fifth axis | Four axes are not yet proven live |
| Scenario packs distributable between organisations | Needs users first |
| Findings synced to an issue tracker | Needs users first |

---

## Deliberately not planned

| Not doing | Why |
|---|---|
| A full web portal | the static report plus a Live Artifact covers the need; a portal is a second product |
| An LLM judge for verdicts | see [ADR 0002](adr/0002-deterministic-verdict.md) |
| An LLM judge for risks | same argument, one level upstream; see [ADR 0009](adr/0009-repository-first-golden-path.md) |
| Generic `execute_shell` / `query_database` tools | see [ADR 0003](adr/0003-constrained-mcp-tools.md) |
| Production targets | `production` is absent from the environment enum by design |
| Autonomous red-team agent | the value is in the contract and the verdict, not in generating more attacks |

The last row is the strategic bet. Attack generation is getting cheap and will
keep getting cheaper. Knowing whether your blue side would have noticed does not
get cheap, and nothing else in the ecosystem is answering it.
