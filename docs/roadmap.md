# Roadmap

Honest status. Anything marked ✅ has tests; anything marked 🟡 is written but not
exercised against a live system; 🔲 is not built.

## Built

| Component | Status | Notes |
|---|---|---|
| Scenario schema + Attack–Detection Contract | ✅ | `schemas/scenario.schema.json`, 4 worked examples |
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
| OWASP Agentic Top 10 coverage reporting | ✅ | 4/10 categories covered by the bundled scenarios |

## Written, not yet proven against a live system

| Component | Status | What is missing |
|---|---|---|
| MCP server (FastMCP binding) | 🟡 | contract and dispatch are tested; not run against a real client in CI |
| Promptfoo executor | 🟡 | config generation and output parsing written; needs a real agent to validate |
| Wazuh OpenSearch collector | 🟡 | query shape written against the `wazuh-alerts-*` mapping; untested live |
| OTel HTTP collector | 🟡 | Tempo-style search API; untested live |
| HTTP target adapter | 🟡 | assumes `{"reply": ...}`; real agents will need per-target shims |

Do not treat 🟡 rows as production-ready. The deterministic core is; the
integrations are first drafts.

## Next

**Near term — earn the CI gate**

- [ ] Run against one real staging agent end to end, and fix what that reveals
- [ ] Wazuh rule pack for the four bundled scenarios (`100501`, `100610`, `100720`, `100810`)
- [ ] A promptfoo custom provider that resolves `target_id` server-side
- [ ] `agentsec init` to scaffold a workspace
- [ ] Migration runner before `SCHEMA_VERSION` reaches 2

**Medium term — team adoption**

- [ ] Read-only remote gateway with OAuth (deployment option C)
- [ ] Evidence redaction on the export path — transcripts contain the leak
- [ ] Live Artifact dashboard reading the normalised JSON
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
