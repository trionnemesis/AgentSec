# ADR 0003 — No generic-capability MCP tools

**Status:** Accepted · **Date:** 2026-07-28

## Context

A purple-team harness needs to run commands, query databases, call HTTP endpoints
and read logs. The direct way to expose that over MCP is a handful of general
tools:

```
execute_shell(command)
query_database(sql)
call_any_url(url, method, body)
run_arbitrary_prompt(prompt)
modify_wazuh_rule(rule_id, content)
```

Five tools, and the model can do anything the harness can do. Very little code.

The problem is that every other control becomes theatre. The target allowlist is
advisory once `call_any_url` exists. The approval flow is advisory once
`execute_shell` exists. The audit log records `execute_shell` and tells a future
investigator nothing about intent. And the blast radius of a prompt injection —
in a tool whose entire job is handling adversarial text — becomes the runner's
full network and filesystem access.

This tool reads attacker-controlled content by design. Poisoned documents,
injected tool responses, hostile transcripts. Assuming none of it will ever
influence a tool call is not a defensible assumption for this particular product.

## Decision

Eleven tools, each narrow. No generic capability. Callers name a target by id and
the service resolves everything else from the operator-owned allowlist.

```json
{ "target_id": "order-agent-staging", "scenario_ids": ["AGT-XPIA-001"], "profile": "pr" }
```

Three enforcement mechanisms, in ascending order of reliability:

1. **Documented** in this ADR and the README.
2. **Structural** — the tool surface is declared as data in `mcp/contract.py`,
   with `additionalProperties: false` on every schema.
3. **Executable** — `tests/test_mcp_contract.py` fails the build if a forbidden
   tool name or parameter name appears:

```python
FORBIDDEN_PARAM_NAMES = {"url", "endpoint", "command", "sql", "query",
                         "path", "token", "password", "headers", ...}
```

A pull request adding `execute_shell` does not need to be caught in review. It
turns CI red.

## Alternatives rejected

**Generic tools plus a prompt telling the model to be careful.** Rejected: a
prompt is not a control. It does not survive an injection, and it produces no
audit trail worth reading.

**Generic tools behind human confirmation on every call.** Rejected: confirmation
fatigue is real and fast. After the twentieth `execute_shell` prompt, approval is
reflexive, and the control has inverted into a rubber stamp.

**A `query_database(sql)` tool restricted to `SELECT`.** Rejected: SQL parsing to
enforce read-only is a known-hard problem, and it still exposes every table the
connection can reach. The state-diff collector instead reads *target-declared
logical collections*, and the collector raises if the target reports a collection
the operator never declared.

**An `approve_run` MCP tool.** Rejected outright. A model able to grant the
approval its own request just triggered does not have an approval requirement.
`agentsec approve` is CLI-only, and a test asserts no tool grants approvals.

## Consequences

**Accepted cost.** New operations need a new tool with a real schema. That is
slower than exposing a shell, and the friction is the feature: each addition is a
deliberate widening of what the model can reach, visible in a diff.

**Accepted cost.** Some legitimate work is not reachable over MCP at all — adding
a target, editing a Wazuh rule, granting an approval. All are CLI or code-review
operations. This is intentional.

**Gained.** The worst outcome of a fully successful prompt injection against this
gateway is a run against an already-allowlisted staging target, recorded in the
audit log. That is a bounded, boring failure, which is the goal.
