## What changed

<!-- One or two sentences. What does this let someone do that they could not before? -->

## Type

- [ ] New scenario (Attack–Detection Contract)
- [ ] Evidence collector
- [ ] Executor
- [ ] Evaluator / verdict logic
- [ ] MCP gateway surface
- [ ] Docs / ADR
- [ ] Fix

## Purple coverage

<!-- Delete rows that do not apply. -->

| Question | Answer |
|---|---|
| Which scenario(s) cover this change? | |
| Does it change how a verdict is produced? | |
| Does it widen what the MCP gateway can reach? | |

## Checks

- [ ] `make check` passes (ruff, mypy, pytest)
- [ ] `agentsec validate --strict` passes
- [ ] `agentsec run --target demo-agent-fixture --profile nightly` still exits 1
      with exactly `AGT-TENANT-001` and `AGT-MEMPOIS-001` blocking

### If this adds or changes a scenario

- [ ] All four axes considered; `response: not_tested` used honestly rather than aspirationally
- [ ] `must_fire` assertions specify a `rule_id`, not only a level
- [ ] Output assertions in multi-principal scenarios are scoped with `in_step` / `as_principal`
- [ ] Mapped to OWASP Agentic / MITRE so it appears in coverage
- [ ] `gate: blocking` only if the scenario has been stable across nightlies

### If this touches the MCP surface

- [ ] The capability exists on `HarnessService` first, so CLI and CI reach it too
- [ ] Input schema is closed (`additionalProperties: false`) and carries no locator,
      credential or free-text-command parameter
- [ ] `tests/test_mcp_contract.py` still passes

### If this adds an evidence collector

- [ ] Normalises into `schemas/evidence.schema.json`; the evaluator is untouched
- [ ] A collection failure surfaces as a `CollectorError`, degrading its axis to
      `error` rather than to `pass`

## Notes for the reviewer

<!-- Anything you are unsure about, or a decision you would like challenged. -->
