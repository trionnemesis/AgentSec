# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

AgentSec is a purple-team harness for AI agents. A scenario YAML declares an
**Attack–Detection Contract** (what the attack does, and what prevention /
detection / evidence / response should look like), and a deterministic
evaluator with no model, clock or network in the decision path turns
collected evidence into one of six verdicts: `error`, `detection_gap`,
`prevention_gap`, `evidence_gap`, `response_gap`, `secure` (that precedence
order matters — see `resolve_verdict` in `evaluation/`). An axis nobody
asserted on evaluates to `not_tested`, never to a pass.

This repo is itself one of the "AI agent repositories" AgentSec inspects:
`.agentsec/project.yaml` declares its own `.claude/` surfaces, and
`agentsec scan` can be pointed at this checkout.

Full narrative docs, the scenario contract format, the MCP tool/resource
table, and the CLI reference all live in `README.md` — read it before
`docs/architecture.md` for the sequence-diagram walkthrough of one run, and
`docs/adr/` for the decisions with their rejected alternatives.

## Commands

```bash
pip install -e '.[dev]'      # core + pytest/ruff/mypy
pip install -e '.[mcp]'      # + the MCP gateway (mcp>=1.2,<2 — pinned below 2.0.0)
pip install -e '.[otel]'     # + OpenTelemetry collector
pip install -e '.[pyrit]'    # + PyRIT executor

make check                   # local ruff + mypy + pytest; CI adds coverage and separate jobs
make demo                    # offline pipeline; the expected run exit 1 is ignored by Make
make report                  # regenerate HTML/JSON/JUnit from stored runs
make schemas                 # regenerate JSON Schema for Run/Verdict/Finding from the pydantic models

pytest -q                                          # whole suite
pytest -q tests/test_evaluator.py                  # one file
pytest -q tests/test_evaluator.py::test_verdict_precedence  # one test
pytest -q -m "not integration"                     # skip tests needing a live external system
ruff check src tests
mypy                                                # config lives in pyproject.toml, not a CLI flag

agentsec scan                                       # inspect *this* repo's own agent surface
agentsec validate --strict                          # lint the scenario catalogue
agentsec preview --target demo-agent-fixture --profile nightly
agentsec run --target demo-agent-fixture --profile nightly --html   # exits 1: two blocking findings by design
```

Coverage floor is `72%` (`[tool.coverage.report] fail_under`, only enforced
when pytest runs with `--cov`, which CI does) — raise it, never lower it.
The `mcp` extra is deliberately **not** installed in the main CI job; if a
non-gateway test ever needs it, that is a sign the gateway stopped being a
thin layer over `HarnessService`.

## Architecture

```
schemas/               JSON Schema for scenario, target, evidence, project manifest, dashboards
scenarios/              The scenario catalogue (eight worked examples)
policy/                 Target allowlist, run profiles, approval ledger — reviewed like a firewall change
fixtures/               Recorded OTel/Wazuh/audit/state corpus so the whole pipeline runs offline
.agentsec/project.yaml  This repo's own project manifest (see "What this repository is")

src/agentsec/
├── models/            typed contracts crossing every layer boundary
├── project/           selected-project resolution and surface discovery (for `agentsec scan`)
├── inspect/            deterministic repository risk rules → the risk plane
├── posture/            static posture ingestion; which findings a scenario can settle
├── scenario/           loader, three-layer validator, catalogue + coverage
├── policy/             allowlist, profiles, approvals, the single `PolicyGuard.check`
├── execution/          red executors (replay, promptfoo, pyrit) + target adapters
├── evidence/            collectors: OTel, Wazuh, tool audit, DB state diff → evidence.schema.json
├── evaluation/          the four axes and `resolve_verdict`
├── reporting/           normaliser → JUnit / HTML / JSON; publication projections
├── store/               SQLite: runs, findings, audit log
├── service/             HarnessService — the internal API (see rule below)
└── mcp/                  gateway: tool contract, resources, prompts, server binding
```

**The one rule that keeps this from eroding: a capability lands on
`HarnessService` (`service/harness.py`) before it lands on the MCP gateway
(`mcp/contract.py`)**. That keeps policy and execution reusable by CLI and CI;
add explicit CLI wiring when an operation should be user-facing there. Core
behaviour tests call the service directly, while `test_mcp_contract.py` and
`test_mcp_gateway.py` cover the gateway boundary.

The local stdio gateway validates arguments, controls the exposed tool/resource
surface, projects outputs and delegates. `PolicyGuard`, approval checks and run
audit remain in the service. Authentication and RBAC belong to the remote
deployment layer, not to the local gateway.

Practical implications when extending:

| Change | Touch | Leave alone |
|---|---|---|
| new attack technique | `scenarios/*.yaml` | all code |
| new SIEM / evidence source | `evidence/<name>.py`, `models/target.py`, `evidence/collector.py`, and `schemas/target.schema.json`; raise `EvidenceUnavailable` on failure | `evaluation/` |
| new attack runner | `execution/<name>.py` + `execution/registry.py` | `evaluation/` |
| new assertion kind | `models/scenario.py`, `evaluation/axes.py`, `scenario.schema.json` | collectors |
| new output format | `reporting/`, `service/harness.py::generate_report`, CLI format help, and the MCP `formats` enum | `evaluation/` |
| new operation exposed to Claude/CI | `service/harness.py` **first**, then `mcp/contract.py`; add `cli.py` when CLI parity is intended | `evaluation/` |

Two invariants enforced by tests, not just convention:

- **An uncollectable evidence source degrades its axis to `error`, never to
  `pass`.** `tests/test_pipeline.py::test_missing_evidence_file_degrades_to_error_not_pass`
  guards this; it's the most dangerous failure mode this tool can have.
- **No generic-capability MCP tools** (`execute_shell`, `query_database`,
  `call_any_url`, `run_arbitrary_prompt`, or anything that would let a model
  mint its own approval). Every tool schema sets `additionalProperties:
  false`, and `tests/test_mcp_contract.py` fails the build if a `url`, `sql`,
  `command`, `path` or `token` parameter appears anywhere on the surface.

`production` is not a member of the target `environments` enum — there is no
flag that turns it on.

## Working in this repo under Claude Code

This repository wires its own `.claude/settings.json` permissions and
`.claude/hooks/guard_agentsec.py` PreToolUse hook (see `.claude/README.md`),
which apply to this session too:

- `agentsec run` via Bash is **denied** so agent-triggered runs use the MCP
  actor and the session's MCP permission path. The CLI itself still delegates
  to `HarnessService`, runs `PolicyGuard.check`, and records audit entries.
  Use `agentsec_start_run` (requires the `agentsec` server from `.mcp.json`);
  read-only subcommands (`validate`, `preview`, `targets`, `scenarios`,
  `coverage`, `get-run`, `compare`, `finding list`, `validate-detection`,
  `mcp-contract`, `audit`) are allowed directly.
- Direct `Write` / `Edit` / `NotebookEdit` operations targeting
  `policy/targets.yaml`, `policy/approvals.yaml` or `fixtures/` are refused.
  These operator-owned files must not be changed through Bash or another
  mechanism either; the hook does not infer file writes from arbitrary Bash.
- Bash commands referencing a production-looking host are refused (broad
  matching on `prod`, `live`, `.com`, `billing`, etc., with an exemption for
  loopback/`.local`/`.svc`/`.internal`/`example.*`).
- `agentsec report`, `agentsec approve` and `agentsec finding promote` prompt
  for confirmation rather than running automatically.

Per-target credentials are referenced **by variable name** from
`policy/targets.yaml`; a credential value must never appear in a scenario, a
target definition, or a tool argument.

## Conventions from CONTRIBUTING.md

- **Adding a scenario**: copy the closest file in `scenarios/`, run
  `agentsec validate --scenario <id> --target <target> --strict`, write all
  four contract axes (a `red_only` validator warning should be treated as an
  error — a prevention-only scenario can't distinguish a fix from a silent
  bypass), add a fixture set under `fixtures/<target>/`, and start the
  regression at `gate: warning` before promoting to `blocking` after a week
  of stable nightlies.
- **Commit messages** explain the reasoning, not the diff (e.g.
  `feat(evidence): rebase fixture timelines into the run window`, not
  `update wazuh.py`).
- For `agentsec run`, exit codes are `0` no blocking finding, `1` a
  blocking finding, and `2` usage/configuration/policy failure. Other
  subcommands may use `1` for command-specific validation failure.
