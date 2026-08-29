---
name: agentsec
description: >
  Purple-team an AI agent with AgentSec: triage a repository's agent attack
  surface first, then author one reviewed Attack-Detection Contract, plan
  reproducible red execution and correlated blue evidence, investigate
  non-secure verdicts, and turn fixes into blocking regressions. Use when asked
  to security-test an agent, triage an agent repository, write or review a
  purple-team scenario, investigate a detection gap or finding, or assess
  whether a change needs new purple coverage.
---

# AgentSec workbench

You are the engineering workbench, not the execution engine. You triage risk,
author one reviewed Attack-Detection Contract, read structured results, locate
responsible code, and prepare fixes and regressions. The deterministic harness
decides pass/fail — never assert a verdict yourself.

The Red and Blue references split operational detail for progressive
disclosure. They are lanes inside this single skill, not independently
executable skills or new product surfaces. One contract must continue to bind
the reproducible stimulus to prevention, detection, evidence and response.

The playbook has four phases, in order:

```text
Repository risk triage → Red execution plan → Blue evidence plan → Purple remediation
```

## Non-negotiables

1. **Triage before you author.** Start from `agentsec://project/risks` or
   `agentsec scan`, never from a blank scenario file.
2. **Preview before you run.** Call `agentsec_preview_run` and show the user
   what would execute. This is a required workflow convention, not a
   server-enforced precondition of `agentsec_start_run`.
3. **Never claim a verdict.** Report exactly what the harness returned.
4. **Never mint approvals.** No MCP tool grants them. If a scenario needs one,
   tell the user to run
   `agentsec approve --scenario <id> --target <id>` and stop.
5. **Unknown or untested is never a pass.** `not_tested`, `not_verifiable`,
   `configuration_only`, `not_detected` and `unsupported` cannot be reported
   as secure.
6. **Check the plumbing before believing a gap.** Call
   `agentsec_validate_detection` first. Backend, source and correlation
   failures are pipeline errors, not evidence that a control is secure.

## 1. Repository risk triage

Read `agentsec://project/risks`, or drive the golden path from a checkout:

```text
agentsec init → agentsec scan → agentsec scan --verify -t <target> → agentsec dashboard
```

Keep the two returned states separate:

- **Runtime fingerprint:** `confirmed`, `likely`, `configuration_only`,
  `not_detected`, `unsupported`. Only the first two identify a runtime agent.
  The others are configuration or discovery states, never a security pass.
- **Risk verification:** `verified`, `verifiable`, `not_verifiable`.
  `not_verifiable` is a catalogue, adapter or evidence coverage gap.

Only a `verifiable` risk enters contract authoring. Do not invent a prompt,
URL, shell command, target path or adapter operation to make a
`not_verifiable` risk green. Report the coverage gap and stop.

## 2. Red execution plan

When the task reaches attack-step design, target compatibility, prevention
assertions, approvals or cleanup semantics, read
[the Red execution lane](references/red-execution.md), then return here for
the Blue evidence plan.

The Red lane cannot independently produce an executable scenario. A reviewed
contract still needs meaningful Blue assertions.

## 3. Blue evidence plan

When the task reaches collectors, deadlines, run correlation, audit
completeness or response assertions, read
[the Blue evidence lane](references/blue-evidence.md), then return here for
Purple remediation.

The Blue lane cannot independently issue a verdict or reinterpret a harness
result.

## 4. Purple remediation and regression

| Verdict / axes | First action | Required remediation |
|---|---|---|
| `error` | stop; draw no security conclusion | fix the backend, schema, correlation, collector or execution pipeline, then rerun |
| `detection_gap`, prevention `pass` | Blue gap only | add telemetry, mapping or a rule; do not change a control with no evidence of failure |
| `detection_gap`, prevention `fail` | both sides failed | fix the application or policy control and detection; retain regression evidence for both |
| `prevention_gap` | detection saw the attempt | fix the application or policy control and retain the existing detection regression |
| `evidence_gap` | the run cannot be reconstructed | add the required span, audit record, state snapshot or correlation metadata |
| `response_gap` | the signal was seen but not acted on | add real response automation or runbook integration, or honestly restore `not_tested` |
| `secure` | verify coverage and provenance | say only that every asserted axis held; list `not_tested` axes and `recorded`, `mixed` or `live` provenance |

For `detection_gap`, read the prevention axis before deciding what to change.
Prevention `pass` means the control held and the Blue side needs work.
Prevention `fail` means both the control and detection need fixes. This
preserves ADR 0004 and does not alter verdict precedence.

A recorded-fixture `secure` result is not live proof. Until a single-run
resource reliably carries provenance, read it from
`agentsec_generate_report` or `agentsec://dashboard/latest`.

## Investigating a finding

1. Read `agentsec://findings` and
   `agentsec://runs/{run_id}/evidence`.
2. Call `agentsec_validate_detection`.
3. Locate the responsible code and cite `file:line`.
4. Apply the remediation matrix above.
5. Call `agentsec_create_regression_draft` and show its complete YAML.
6. Do not mark the finding verified; only a passing run can do that.

## Tool surface

`agentsec_start_run` is the only MCP tool that executes an attack against an
allowlisted target. `agentsec_promote_finding` and
`agentsec_generate_report` perform local writes only. The other eight tools
are read-only.

Do not maintain an exhaustive hand-copied tool or resource list here. Run
`agentsec mcp-contract` or read `src/agentsec/mcp/contract.py`, which is the
source of truth. There is deliberately no shell, SQL, arbitrary-URL,
arbitrary-prompt or approval-minting tool.

## Comparing runs

Check `contract_changed` before interpreting a verdict difference. If the
contract changed, the difference is not evidence of a system regression.

## Guidance is not the boundary

This skill and its lane references are advisory text. Enforced runtime
boundaries live in `PolicyGuard.check`, the closed MCP schemas,
`.claude/settings.json`, `.claude/hooks/guard_agentsec.py`, and their tests.
A PR adding a safety invariant must name its enforcement file; otherwise
describe it explicitly as workflow guidance.

The Phase 0 `skill_eval` static profile checks package structure, local
references, scripts and pinned digests. It does not run this playbook or prove
that a model followed the six non-negotiables; those behavioural evaluations
remain deferred.

## Repository references

- `docs/attack-detection-contract.md` — four-axis authoring contract
- `docs/architecture.md` — layer boundaries
- `docs/adr/0004-detection-outranks-prevention.md` — verdict precedence
- `docs/adr/0008-skill-assurance-bounded-context.md` — static versus dynamic skill assurance
- `docs/adr/0009-repository-first-golden-path.md` — repository-first triage
- `docs/roadmap.md` — named coverage gaps and parked work
