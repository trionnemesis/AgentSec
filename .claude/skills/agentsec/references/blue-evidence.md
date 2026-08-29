# Blue evidence lane

Read this reference when the shared contract needs detection, evidence or
response planning, or when a returned gap must be diagnosed.

This is a lane inside the single AgentSec workbench, not an independently
executable Blue skill. It cannot produce an executable scenario or verdict on
its own; both lanes remain bound by one reviewed Attack-Detection Contract.

## Four independent deadlines

| Boundary | Meaning |
|---|---|
| Attack timeout | maximum execution time from `spec.attack.timeout_seconds` |
| Telemetry settle | time collectors may poll for required signals |
| Detection SLA | `within_seconds` on a `must_fire` assertion |
| Response SLA | `within_seconds` on an `expected_action` assertion |

Detection and response SLAs are evaluated against the evidence event timestamp,
not the time at which a collector observed the event. Polling can make a
delayed signal visible; it cannot make that signal timely.

## Current-run correlation

Live Wazuh, OTel and tool-audit evidence must correlate to the canonical
`agentsec.run_id` of the current run.

Missing, conflicting or foreign-run correlation is pipeline `error`, not
`detection_gap`, `evidence_gap` or `secure`. The bundled recorded-file fixture
corpus is the sole documented compatibility exception.

Never allow evidence from another run to satisfy the current contract.

## Audit completeness is per invocation

Evaluate `every_tool_call_audited` one invocation at a time:

1. Prefer `tool_call_id` or `span_id` for one-to-one matching.
2. If no traced call has invocation identifiers, use the documented multiset
   key: mandatory tool name plus whichever of `decision`, `principal`,
   `arguments_digest` and `policy` the trace carries.
3. Consume each audit record once.

Two same-named traced calls cannot be satisfied by one audit record. A trace
where only some calls carry identifiers is `error`, not a fallback candidate.

## Fail closed on pipeline faults

The following are pipeline `error`:

- a required backend is unavailable;
- Wazuh pagination fails or does not consume every required page;
- a required evidence source is absent;
- run correlation is missing, conflicting, foreign or undecidable.

Do not downgrade these conditions to detection or evidence gaps. Before
remediating an apparent `detection_gap`, call
`agentsec_validate_detection` to separate missing plumbing from a real rule or
telemetry gap.

## Response honesty

Keep:

```yaml
response:
  mode: not_tested
```

until a real runbook or automation exists and can be observed. Do not create a
passing response assertion solely to fill coverage.

## Named coverage routes

These are existing roadmap items, not implementation scope for this slice:

- Add the Wazuh rule pack for the original bundled rules `100501`, `100610`,
  `100720` and `100810`.
- Add rules `100901`–`100904` for `AGT-CONFIG-001..004`.
- Record the corresponding fixtures so the relevant verification path can run
  offline.

Do not implement the rule packs or fixture corpus in this docs-and-static
evaluation slice.

## Return to the shared workflow

Before returning to `SKILL.md`, confirm that:

- all four time boundaries are distinguished;
- live evidence has canonical current-run correlation;
- audit matching is per invocation;
- backend and correlation failures remain `error`;
- response stays `not_tested` without real response capability.

Apply the shared Purple remediation matrix in `SKILL.md`.

## Guidance is not enforcement

This reference is guidance, not an enforcement boundary. A new safety
invariant must land in the service, schema, permissions, hook or tests and
name that enforcement file in the PR.
