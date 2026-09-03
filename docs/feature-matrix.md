# Feature matrix

Converges [#32](https://github.com/trionnemesis/AgentSec/issues/32). One golden
path, and every capability classified by what it does for that path.

The problem #32 named was not that any single capability was wrong. It was that
the repository had accumulated five product surfaces — purple execution, CI
gates, Claude/MCP/Desktop integration, project discovery, static posture
ingestion — each defensible on its own, none of them ordered relative to the
others, so a new engineer could read the README and still not know what to run
first.

This document fixes the order. It does not remove anything that works.

---

## The golden path

```
agentsec init                     select the repository
agentsec scan                     find the attack surface and rank it
agentsec scan --verify -t <id>    hand the provable high-risk subset to the harness
agentsec dashboard --html results/dashboard.html  render it, or read agentsec://project/risks live
```

Stated once, in one sentence:

> An engineer opens a local repository. AgentSec finds the AI-agent attack
> surface in it — agents, skills, MCP servers, hooks, tool grants, memory — and
> ranks what it finds. The subset that a scenario can actually settle goes to
> the Purple Harness, which returns a deterministic verdict on whether the
> attack works and whether anyone would have seen it.

Everything below is classified by its relationship to that path.

### Why repository-first rather than CI-first

#32 proposed converging on the PR/CI gate (`agentsec check`). This document
converges one step earlier, on the repository scan, for a reason the gate
proposal exposes rather than contradicts:

**The CI gate cannot be the entry point, because reaching it requires a
configured target.** A target means an allowlist entry, a staging agent, and
usually a Wazuh or OTel backend — work owned by a security or platform team that
most engineers evaluating AgentSec do not have. An entry point that first
requires someone else's sprint is not an entry point.

`agentsec scan` requires none of that. It runs against a repository and nothing
else, and it produces the one thing that makes the gate worth configuring: a
specific, named list of what in *this* repository is worth testing. The CI gate
is still the destination. It is now the second step rather than the first.

---

## Core — the golden path itself

Changes here need an ADR. These are load-bearing.

| Capability | Where | Role on the path |
|---|---|---|
| Attack–Detection Contract + four-axis evaluator | `evaluation/` | The product. Everything else exists to feed it or read it. |
| Verdict precedence | `evaluation/axes.py` | `error > detection_gap > prevention_gap > evidence_gap > response_gap > secure`. Frozen. |
| Selected-project resolution + manifest | `project/` | Which repository. A process-boundary decision, never a tool argument ([ADR 0003](adr/0003-constrained-mcp-tools.md)). |
| Surface discovery | `project/discovery.py` | Agents, skills, hooks, settings, instructions, MCP servers, tool grants, memory. Inventory only. |
| Runtime framework fingerprint | `project/fingerprint.py` | Distinguishes application runtime agents from Claude Code, Codex, Gemini CLI, Cursor and MCP development configuration without importing repository code. Composed into the `project` plane, so `scan`, the dashboard and the MCP resource read one classification. |
| Repository risk plane | `inspect/` | Turns the inventory into ranked risks, and each risk into `verified` / `verifiable` / `not_verifiable` ([ADR 0009](adr/0009-repository-first-golden-path.md)). |
| `config-surface:` correlation | `scenario/surface_tags.py` | The one bridge from a static surface to a runnable scenario, shared by the risk and posture planes so neither can disagree about a surface match. The posture plane additionally requires a `threat-class:` tag match before calling a finding `covered` ([#68](https://github.com/trionnemesis/AgentSec/issues/68)); the risk plane cannot yet apply that requirement because a `RepoRisk` carries no scanner-emitted category to match against. |
| Replay executor + fixture corpus | `execution/replay.py` | Deterministic. What CI relies on. |
| Run provenance | `RunSummary.provenance` | `recorded` / `live` / `mixed`. A fixture-derived `secure` is never presented as a live one ([#27](https://github.com/trionnemesis/AgentSec/issues/27)). |
| Policy guard, approvals, target allowlist | `policy/` | One decision point for CLI, MCP and CI. `production` is not expressible. |
| Publication projection | `reporting/publish.py` | Fail-closed. An output kind with no policy is refused, not sent. |
| CLI exit codes | `cli.py` | `0` success · `1` command-specific blocking/invalid result · `2` could not tell. The distinction is the gate's credibility. |

### The rule that keeps the planes apart

Five planes are composed in `agentsec://dashboard/latest`. None of them is
merged into another, and this is the constraint most likely to be eroded by a
well-meaning change:

| Plane | Answers | Vocabulary |
|---|---|---|
| `purple` | Did the attack work, and would the blue side have seen it? | `PurpleVerdict` |
| `repo_risk` | What in this repository is worth testing? | `inspected` / severity / `verified`–`verifiable`–`not_verifiable` |
| `skill_assurance` | Do this repository's skills behave? | `pass` / `fail` / `not_tested` |
| `static_posture` | What did a third-party scanner flag? | `ingested` / `covered`–`not_tested`–`n/a` |
| `project` | Which repository is this, and is it an agent? | `declared` / `not_initialised` / `invalid`, and `confirmed`–`likely`–`configuration_only`–`not_detected`–`unsupported` |

Each status enum is spelled differently on purpose. A single number averaging
them would answer none of the four questions, and the fastest way to build one
by accident is to give two planes the same words.

The Phase 0 `agentsec skill validate --profile static` command is not a sixth
plane and does not populate `skill_assurance`. It is a model- and credential-free
package-integrity gate over current workspace bytes and a reviewed
`SkillEvalSuite`: strict frontmatter, declared lane assets and scripts, exact
SHA-256 pins, and parsed Markdown destinations. It is not a semantic prose or
bare-URL scan. Its report is stdout-only; dynamic skill behaviour remains
`not_tested`.

---

## Supporting — earns its place by serving the path

Useful, and not the product. A change here should be justified by what it does
for the golden path.

| Capability | Status | Position |
|---|---|---|
| Finding workflow | Built | The fix loop after a verdict. Engineer-facing states are `open → fixing → verified`; the full transition table is expert mode. |
| Report normaliser → JUnit / HTML / JSON | Built | How CI and tickets consume a run. |
| Live Artifact dashboard page | Built | An alternative *interface* to the same published DTO. Never a source of capability the CLI lacks. |
| MCP gateway | Built, thinly proven | An adapter. `HarnessService` is the API; the gateway may not grow behaviour the CLI does not have. |
| Claude Desktop / Cowork packaging | Built, manual | Read-only registration for the Artifact path. |
| Static posture ingestion | Built | Opt-in. Requires a third-party scanner's report; absent by default and `not_tested` when absent ([#25](https://github.com/trionnemesis/AgentSec/issues/25)). |
| Phase 0 static skill-package gate | Built | `skill_eval/` validates structure and integrity in a separate fail-closed workflow. It does not execute the workbench, judge model behaviour, write a store/dashboard, or produce a Purple verdict ([#64](https://github.com/trionnemesis/AgentSec/issues/64)). |
| Scenario authoring: `validate`, `preview`, `approve`, `validate-detection` | Built | Expert mode. Engineers on the golden path do not write scenario YAML. |
| OWASP Agentic Top 10 coverage | Built | Reporting, not a gate. |

---

## Experimental — real code, unproven against a live system

Do not put these on the golden path, and do not describe them as ready.

| Capability | Missing |
|---|---|
| Promptfoo executor | A real agent to validate against |
| Wazuh OpenSearch collector | Any live run |
| OTel HTTP collector | Any live run |
| HTTP target adapter | Per-target shims; it assumes `{"reply": ...}` |
| Remote read-only gateway | Authentication — OAuth/OIDC, RBAC, TLS termination |

---

## Parked — not started, and not next

Frozen until the golden path has adoption evidence. Parking is not rejection; it
is refusing to widen the surface while the middle of it is unproven.

| Capability | Why parked |
|---|---|
| Dynamic Skill Assurance (Phase 1/2) | Model-driven or executable skill behaviour still needs a separate runner, store and verdict workflow ([ADR 0008](adr/0008-skill-assurance-bounded-context.md)). Phase 0 validates package structure only, so the plane reports `not_tested` honestly today. |
| PyRIT executor | Attack generation is the cheap half. Adding a third executor before one live path works buys nothing. |
| pytest executor | Same. |
| MITRE ATLAS coverage | A second taxonomy over the same eight scenarios. |
| Multi-agent scenarios | Needs per-agent step targeting. |
| Cost/latency as a fifth axis | Four axes are not yet proven live. |
| Cross-organisation scenario packs | Needs users first. |

---

## Deliberately not built

| Not doing | Why |
|---|---|
| An LLM judge for verdicts | [ADR 0002](adr/0002-deterministic-verdict.md) |
| Generic `execute_shell` / `query_database` MCP tools | [ADR 0003](adr/0003-constrained-mcp-tools.md) |
| Production targets | `production` is absent from the environment enum by design |
| A full web portal | The static page plus a Live Artifact covers it; a portal is a second product |
| Autonomous red-team agent | The value is the contract and the verdict, not more attacks |
| An LLM judge for *risks* | Same argument as ADR 0002, one level upstream. A risk plane whose output changed between two runs of the same commit could not be diffed or argued with. |

---

## Known gaps on the golden path

Stated here rather than left for a reader to discover, because a matrix that
only lists what works is marketing.

1. **The fingerprint classifies six framework families, not every framework.**
   LangChain/LangGraph, OpenAI Agents SDK, AutoGen, Semantic Kernel, CrewAI and
   framework-neutral Python/Node tool calling. Anything else in a repository that
   is plainly an agent reports `not_detected`, which is why that word means
   "no evidence" and never "no agent" — and why an unparsed file is reported as
   `unsupported` rather than counted as absence.
2. **No scenario covers the tool-grant or settings surface.** `ASI-TOOL-BROAD-GRANT`
   and `ASI-TOOL-PERMISSION-BYPASS` fire — the second at `critical` — and both
   report `not_verifiable`, because no `AGT-CONFIG-*` scenario is tagged at
   `.claude/settings.json`. The plane is honest about it; the catalogue gap is
   real. This is the next scenario to write.
3. **No scenario covers the memory surface as a repository surface.**
   `AGT-XPIA-001` is the right shape but is tagged at no config surface, so
   `ASI-MEMORY-UNREVIEWED-STORE` reports `not_verifiable`.
4. **`AGT-CONFIG-*` has no recorded fixtures.** The family validates clean and is
   scoped to `environments: [ci, staging]`, so `--verify` against the bundled
   `demo-agent-fixture` (environment `local`) correctly refuses with exit 2
   rather than selecting nothing and reporting success. Until fixtures exist,
   `--verify` needs a real staging target.
5. **The catalogue does not travel with the CLI.** `Settings.scenarios_dir` is
   `<workspace>/scenarios`, so in a repository that is not a checkout of
   AgentSec there are no scenarios to triage against and *every* risk resolves
   to `not_verifiable` — correct, and misleading at a glance now that the screen
   above it can say `confirmed langgraph`. Bundling the reviewed catalogue as
   package data is the fix; which catalogue version an installed CLI should
   trust is the question that makes it more than a one-line change.
6. **No end-to-end run against a live agent has happened.** This remains the
   single most valuable open item, exactly as #32 says.

---

## What this convergence changed

| Before | After |
|---|---|
| Discovery produced an inventory nothing consumed | The inventory feeds a risk plane, which feeds the harness |
| No first-party analysis; `static_posture` needed someone else's scanner | `inspect/` runs with nothing configured |
| Tools and Memory/RAG were not discovered at all | Both are surfaces, and both have rules |
| No route from "surface exists" to "scenario to run" | `verification.state` + `verify_queue` |
| `AGT-CONFIG-003` was tagged at one file in one repository | Tagged at `.claude/hooks`, so it correlates anywhere |
| Entry point required a configured target | `agentsec scan` requires a repository |
| Roadmap sorted by completion status | Sorted by Core / Adoption / Experimental |
