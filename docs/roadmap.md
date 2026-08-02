# Roadmap

Honest status. Anything marked ✅ has tests; anything marked 🟡 is written but not
exercised against a live system; 🔲 is not built.

## Built

| Component | Status | Notes |
|---|---|---|
| Scenario schema + Attack–Detection Contract | ✅ | `schemas/scenario.schema.json`, 8 worked examples |
| Three-layer validator | ✅ | JSON Schema → Pydantic → 15 semantic rules |
| Target allowlist + private-address guard | ✅ | `production` not expressible; public hosts refused |
| Policy guard (risk ceiling, quarantine, approvals) | ✅ | single decision point for CLI, MCP and CI |
| Approval tokens (scoped, expiring, single-use) | ✅ | CLI-only; no MCP tool grants them |
| Replay executor + fixture/HTTP adapters | ✅ | deterministic; the one CI should rely on |
| Evidence collectors: Wazuh, OTel, tool audit, state diff | ✅ | file backends tested; timeline rebasing for fixtures |
| Purple evaluator, four axes | ✅ | pure function; ~60 tests |
| Verdict precedence | ✅ | `error > detection_gap > prevention_gap > evidence_gap > response_gap > secure` |
| SQLite store (runs, findings, audit log) | ✅ | latest-run-per-scenario aggregates |
| Finding workflow with enforced transitions | ✅ | cannot verify a detection gap without a detection rule |
| Report normaliser → JUnit / HTML / JSON | ✅ | HTML is self-contained and theme-aware |
| CLI with meaningful exit codes | ✅ | `0` clean, `1` blocking, `2` could not tell |
| MCP contract as data + architectural tests | ✅ | forbidden tool/param names fail the build |
| OWASP Agentic Top 10 coverage reporting | ✅ | 8/10 categories covered by the bundled scenarios |
| `AGT-CONFIG-*` agent-configuration attack family | ✅ | 4 scenarios — poisoned project instructions, hidden-Unicode agent definitions, hook command injection, credential-shaped MCP addition ([#26](https://github.com/trionnemesis/AgentSec/issues/26)); validated clean, `gate: warning` until stable across nightlies against a real target |
| Static posture ingestion (AgentShield JSON / SARIF) | ✅ | `static_posture` plane, correlated against discovered surfaces and executed verdicts, never a fifth axis or a `PurpleVerdict` ([#25](https://github.com/trionnemesis/AgentSec/issues/25)) |
| Run provenance (`recorded` / `live` / `mixed`) | ✅ | `RunSummary.provenance`; a fixture-derived `secure` is labelled as such, never presented like a live one ([#27](https://github.com/trionnemesis/AgentSec/issues/27)) |
| Publication projection for observed data | ✅ | `reporting/publish.py`; transcripts become digests, identities pseudonyms, free-form maps keep keys and lose values |
| Resource allowlist for the report gateway | ✅ | `ResourceSpec.published`; evidence, audit and target authoring detail are not registered under `AGENTSEC_MCP_READ_ONLY=1` |
| Fail-closed publication | ✅ | unknown output kind raises; a resource with no publication policy stops the gateway from booting |
| Versioned dashboard rollup contract | ✅ | `schemas/dashboard.schema.json`, validated against the shipped corpus |
| Selected-project manifest and discovery | ✅ | `.agentsec/project.yaml` + `project/`; relative locations only, traversal and symlink escape refused, nothing absolute in the output |
| Composed project dashboard resource | ✅ | `agentsec://dashboard/latest`; project, purple and Skill Assurance planes kept separate, validated against `schemas/project-dashboard.schema.json` on every read |

## Written, not yet proven against a live system

| Component | Status | What is missing |
|---|---|---|
| MCP server (FastMCP binding) | 🟡 | a real stdio client drives a spawned server in the gateway CI job, so listing, dispatch and the projection are proven over the protocol; no client other than that test has ever connected |
| Promptfoo executor | 🟡 | config generation and output parsing written; needs a real agent to validate |
| Wazuh OpenSearch collector | 🟡 | query shape written against the `wazuh-alerts-*` mapping; untested live |
| OTel HTTP collector | 🟡 | Tempo-style search API; untested live |
| HTTP target adapter | 🟡 | assumes `{"reply": ...}`; real agents will need per-target shims |

Do not treat 🟡 rows as production-ready. The deterministic core is; the
integrations are first drafts.

## Next

**Near term — earn the CI gate**

- [ ] Run against one real staging agent end to end, and fix what that reveals
- [ ] Wazuh rule pack for the four original bundled scenarios (`100501`, `100610`, `100720`, `100810`)
- [ ] Fixture recordings and a Wazuh rule pack for `AGT-CONFIG-001..004` (`100901`–`100904`) —
      proposed for review, not committed: `hooks/guard_agentsec.py` refuses agent writes to
      `fixtures/`. Until recorded, the family validates clean but does not run in nightly
      (scoped to `environments: [ci, staging]`, so it does not select against `demo-agent-fixture`)
- [ ] A promptfoo custom provider that resolves `target_id` server-side
- [x] `agentsec init` for the selected repository, with a committed
      `.agentsec/project.yaml` and one canonical workspace resolver
      ([#20](https://github.com/trionnemesis/AgentSec/issues/20) PR B)
- [ ] **Migration runner — now overdue.** `SCHEMA_VERSION` is already `2`, and
      `store/sqlite.py:_init_schema` writes the version row only when it is
      absent. A database created under version 1 therefore keeps reporting
      version 1 for the rest of its life, and nothing reads that row to decide
      anything. Any database predating the bump is silently mislabelled

**Medium term — team adoption**

- [ ] Read-only remote gateway with OAuth (deployment option C). The gateway
      half is built — allowlisted resources, projected output, fail-closed
      publication. What is missing is authentication: OAuth/OIDC, RBAC and the
      TLS-terminating gateway in front
- [x] A dashboard resource a page can pin to — `agentsec://dashboard/latest`,
      computed in memory and schema-valid ([#20](https://github.com/trionnemesis/AgentSec/issues/20) PR C)
- [x] The dashboard page itself — `agentsec dashboard --html`, the same template
      a hosted Live Artifact renders
      ([#20](https://github.com/trionnemesis/AgentSec/issues/20) PR D)
- [x] Claude Desktop plugin/extension packaging, so a local Cowork session can
      load this server read-only
      ([`packaging/claude-desktop/`](../packaging/claude-desktop/))
- [ ] **Host it.** The page and the resource exist; publishing the Artifact and
      binding it to a Desktop-registered gateway is a manual step today, and the
      end-to-end path has been followed by hand rather than by a test. The
      checklist is in `packaging/claude-desktop/README.md`; three of its seven
      steps are asserted by `tests/test_packaging.py` and four need a person
- [ ] PyRIT executor for nightly exploratory runs
- [ ] pytest executor, so existing security tests join the same verdict model
- [ ] Coverage against MITRE ATLAS alongside OWASP
- [ ] Skill Assurance (`skill_eval`) — [ADR 0008](adr/0008-skill-assurance-bounded-context.md) ·
      [#14](https://github.com/trionnemesis/AgentSec/issues/14). The `static` profile needs no
      model and can land ahead of the staging run; the rest waits on it

**Longer term**

- [ ] Multi-agent scenarios (`AAI005`) — needs step targeting per agent
- [ ] Cost/latency budgets as a fifth axis for denial-of-wallet work
- [ ] Scenario packs distributable between organisations
- [ ] Findings synced to an issue tracker rather than living only in SQLite

## Deliberately not planned

| Not doing | Why |
|---|---|
| A full web portal | the static report plus a Live Artifact covers the need; a portal is a second product |
| An LLM judge for verdicts | see [ADR 0002](adr/0002-deterministic-verdict.md) |
| Generic `execute_shell` / `query_database` tools | see [ADR 0003](adr/0003-constrained-mcp-tools.md) |
| Production targets | `production` is absent from the environment enum by design |
| Autonomous red-team agent | the value is in the contract and the verdict, not in generating more attacks |

The last row is the strategic bet. Attack generation is getting cheap and will
keep getting cheaper. Knowing whether your blue side would have noticed does not
get cheap, and nothing else in the ecosystem is answering it.
