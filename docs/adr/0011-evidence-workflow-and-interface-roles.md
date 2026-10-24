# ADR 0011 — One evidence workflow, with interfaces that do not borrow authority

**Status:** Accepted · **Date:** 2026-10-25

Converges [#32](https://github.com/trionnemesis/AgentSec/issues/32#issuecomment-5199028411)
and [#92](https://github.com/trionnemesis/AgentSec/issues/92). This decision does
not add an executor, verdict axis, tool, or product plane. It fixes the order in
which the existing parts are presented and the authority each part actually has.

## Context

AgentSec now has enough working surfaces that a reader can mistake an interface
for the product or one kind of evidence for another. A repository risk can be
statically detected without a scenario. A reviewed scenario can exist without a
run. A run can produce a deterministic verdict from recorded evidence without
being live proof. The same result can then be viewed through a report, MCP
resource, or Live Artifact without those interfaces having created it.

The corrected product entry point in #32 is the local repository and its
read-only inspection, not a preconfigured staging target. Dynamic verification
is an explicit later action for a selected risk. The public GitHub Pages site is
an introduction to that workflow; it is not the runtime Live Artifact and never
receives a user's evidence.

## Decision

### 1. Present one traceable evidence workflow

Every interface documents and preserves this order:

```text
repository surface and risk
→ reviewed scenario
→ run
→ prevention / detection / evidence / response
→ recorded / mixed / live provenance
→ remediation and regression
```

Each arrow is a boundary, not a cosmetic step:

- A static risk is a reason to investigate. It is not a Purple verdict.
- `verifiable` means a reviewed scenario can exercise the surface. It does not
  mean the scenario ran.
- `verified` means a covering scenario produced a verdict. It is not a synonym
  for `secure`.
- A verdict is read together with all four axes. An unasserted axis remains
  `not_tested`.
- Provenance qualifies what the run observed. `recorded`, `mixed`, and `live`
  do not change the verdict or fill an untested axis.
- Remediation follows the failed axes; only a later passing run verifies a fix.

### 2. Keep six roles distinct

| Role | Owns | Does not own |
|---|---|---|
| Agent/workbench | read-only repository discovery, risk triage, scenario drafting, result reading, and code remediation | target policy, execution authority, or verdict calculation |
| MCP gateway | constrained schemas, projection, and delegation to the service | new capability, approval, policy, or evaluation logic |
| AgentSec skill | workflow guidance and a single Red/Blue-lane router; Phase 0 static integrity pins | permissions, enforcement, execution, or dynamic Skill Assurance |
| Host hook | defense in depth at the coding-agent boundary | replacement for service policy or evidence of a target control |
| Service/evaluator | target policy, bounded execution, evidence collection, four-axis evaluation, precedence, persistence, and reporting queries | UI-derived or model-derived verdicts |
| Live Artifact | read-only presentation of published project, risk, run, axis, provenance, and remediation context | raw private evidence, starting runs, mutating findings, or recomputing results |

The runtime Live Artifact and the public `site/` are deliberately different.
The Artifact consumes the current project's projected DTO through the read-only
gateway. GitHub Pages explains the product with labelled examples and links; it
does not connect to a project or publish user evidence.

### 3. Guidance and host controls do not become service authority

The single `.claude/skills/agentsec/` workbench retains its Red and Blue
reference lanes. The skill can require preview as a workflow convention and can
teach the reader to stop on missing approval, but prose grants no permission.
The Phase 0 static profile proves the reviewed package bytes and local links,
not that a model followed the instructions. Dynamic Skill Assurance remains
`not_tested`.

The host hook rejects unsafe coding-agent tool requests as defense in depth. It
does not replace `PolicyGuard.check`, the target allowlist, approval validation,
collector correlation, or the deterministic evaluator. A hook pass is not a
Purple pass, and a malformed hook request must not be treated as evidence about
the agent under test.

### 4. Read interfaces project stored truth

Reports, dashboard views, and published run resources use service-owned query
derivation and the publication allowlist. They may redact or omit private detail;
they may not infer a better verdict, promote provenance, or turn absence into a
green state. Provenance adapter and collector/backend diagnostics use closed
vocabularies, collapsing unsupported persisted labels to `unknown` and omitting
unsupported source keys instead of echoing them. Unknown, missing, empty, and
collection-error states stay visible.

## External acceptance that remains open

This decision records boundaries; it does not claim external acceptance:

- [#20](https://github.com/trionnemesis/AgentSec/issues/20): a person still has
  to complete the real Claude Desktop/Cowork connection, render, and read-only
  refresh smoke test.
- [#50](https://github.com/trionnemesis/AgentSec/issues/50): local isolated
  consumer tests do not prove a hosted cross-repository caller; a real caller
  Actions URL and artifacts are still required.
- [#86](https://github.com/trionnemesis/AgentSec/issues/86): the Wazuh rule pack
  has static contract coverage, but `AGT-CONFIG-001..005` recordings remain
  operator-owned and live Wazuh acceptance remains unproven.

## Alternatives rejected

**Make MCP or the Artifact the product core.** Both are replaceable interfaces.
Putting policy or evaluation there would create a path CI cannot reuse and a UI
that can disagree with stored results.

**Treat the skill or hook as a permission boundary.** Guidance can be ignored
and a host hook only sees its own tool envelope. Neither can authorize a run or
establish target-side evidence.

**Compress risk, verdict, coverage, and provenance into one status.** A green
`verified` badge could mean only that a failing scenario ran; a green static hit
could imply an attack was blocked without executing it. Separate vocabularies
are required to keep the claims falsifiable.

**Serve raw run evidence to the public introduction site.** Public Pages has no
per-project trust context and no need for private logs. Labelled examples are
enough to explain the workflow.

## Consequences accepted

The first screen can be less celebratory: no run, no evidence, or untested axes
must remain visibly neutral or incomplete. A reader may need to open a detail
view to see all four axes and provenance, but every summary must link back to
that evidence chain. Some installation guidance must distinguish the newest
published release from unreleased `main`; a package version in source is not a
release asset.
