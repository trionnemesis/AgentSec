# ADR 0001 — Four layers, with a hard service boundary

**Status:** Accepted · **Date:** 2026-07-28

## Context

The obvious build is: an MCP server that runs Promptfoo, queries Wazuh, stores
results and renders reports. One process, one repository, ship it in a week.

That shape has three problems that only surface later:

1. **Long work in a request.** A nightly run against a real staging agent takes
   hours. An MCP request cannot be holding that open.
2. **Vendor entanglement.** If the only way to run a test is through an MCP
   client, the security programme now depends on that client's availability,
   pricing and API stability. Security tooling should outlive an AI vendor
   choice.
3. **CI cannot use it.** A merge gate that requires a language model in the loop
   is a merge gate that will be bypassed the first time the model is slow.

## Decision

Four layers, and one boundary that matters:

```
Interaction   Claude Code · Live Artifact
Control       AgentSec MCP Gateway      ← auth, schemas, approval, audit
── the boundary ──
Execution     HarnessService            ← also called directly by CLI and CI
              executors · collectors · evaluator · store
```

`HarnessService` is the internal API. The gateway and CI are **peers** calling it;
neither is privileged. A capability lands in the service before it lands on the
gateway, so the CLI always reaches it too.

Enforced concretely:

- `tests/test_mcp_contract.py::test_all_handlers_exist_on_the_service` fails if a
  gateway tool declares a handler the service does not have.
- The gateway's dispatcher can only call `getattr(service, tool.handler)`. There
  is no place for it to implement anything.
- Every test in `tests/` calls the service. The `mcp` extra is not installed in CI.

## Alternatives rejected

**Everything in the MCP server.** Fastest to build. Rejected: no CI path, no
non-Claude path, and long-running tests inside protocol requests. The cost of
splitting later is a rewrite of every call site.

**Gateway as a thin HTTP proxy to a separate service process.** More operationally
honest for a large deployment. Rejected *for now*: two processes to run before the
Scenario Contract has proven itself is premature. The service boundary is already
a clean seam — promoting it to a network boundary is a later, mechanical change.

**No gateway; Claude Code calls the CLI via Bash.** Tempting, and it does work.
Rejected: `Bash(agentsec ...)` permission is indistinguishable from `Bash(rm -rf)`
to the permission system, so it grants far more than intended. Typed tools with
closed schemas are the point.

## Consequences

**Accepted cost.** More files than a single-process design, and two call paths to
keep in step. The contract test makes the second cost bounded.

**Gained.** Deleting `src/agentsec/mcp/` removes a convenience, not a capability.
That is the difference between adopting an AI tool and depending on one.
