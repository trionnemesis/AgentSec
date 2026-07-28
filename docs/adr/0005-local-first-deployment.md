# ADR 0005 — Local MCP first, remote gateway later

**Status:** Accepted · **Date:** 2026-07-28

## Context

The appealing end state is a Live Artifact dashboard the whole team opens, backed
by a remote MCP connector into the company harness.

The connector model makes that a bigger step than it looks: a remote MCP
connector is dialled **from Anthropic's infrastructure to your server**, not from
the user's machine into your network. So the dashboard requires publishing an
authenticated endpoint that reaches your purple-team control plane. That is OAuth,
an API gateway, TLS, rate limiting, RBAC, audit shipping and a data-minimisation
review — before a single verdict has proven useful.

There is also an under-discussed disclosure question. Even a fully read-only
gateway returns your agents' capabilities, your detection rule ids and your open
unfixed findings. That is a well-organised target package.

## Decision

Ship option B first: local stdio MCP, CLI, SQLite, static HTML report. Nothing
inbound.

Sequence, with an exit gate on each phase:

| Phase | Deliverable | Gate before proceeding |
|---|---|---|
| 1 | Local MCP + CLI + static report | verdicts are changing engineering decisions |
| 2 | CI gate on the `pr` profile | the gate has caught a real regression |
| 3 | Read-only remote gateway + Live Artifact | someone outside security reads it weekly |
| 4 | Full remote gateway, RBAC, approvals | more than one team authors scenarios |

The code is built so this is additive, not a rewrite: `AGENTSEC_MCP_READ_ONLY=1`
already produces the phase-3 gateway from the same codebase, and the phase-4
transport swap does not touch `HarnessService`.

## Alternatives rejected

**Build the remote gateway first.** Rejected: it front-loads all the
infrastructure cost against an unproven contract format. If phase 1 reveals that
the Scenario Contract does not express your real threats — the most likely way this
project fails — you would rather learn it after a week than after a quarter of
platform work.

**Skip MCP; CLI only.** Defensible, and the CLI genuinely covers everything.
Rejected because scenario *authoring* is where a model earns its place: reading a
repository, finding the authorisation check, and drafting the contract is exactly
the work Claude Code is good at, and typed tools beat asking it to shell out.

**Live Artifact reading the SQLite file directly.** Rejected: an artifact cannot
reach a file on a developer's machine, and shipping the database to a hosted page
publishes every transcript in it — including the transcripts of tests that
successfully exfiltrated data.

## Consequences

**Accepted cost.** No team dashboard on day one. Mitigated by the static HTML
report, which is self-contained, attaches to a ticket, and opens from a CI
artifact zip on a machine with no network.

**Accepted cost.** Results live per-developer until phase 3, so coverage numbers
are not yet team-wide. Acceptable while the question being answered is "does this
verdict tell us anything", not "what is our aggregate posture".

**Gained.** Phase 1 has no infrastructure dependency and no security review to
schedule, so it can start this week. The most expensive phases stay behind gates
that require evidence of value.

**Revisit when:** connector behaviour changes materially, or a team hits the
phase-2 gate and wants shared reporting. Check Anthropic's current docs rather
than this ADR for the connector mechanics — that is the detail most likely to have
moved.
