# Contributing

## Setup

```bash
pip install -e '.[dev]'
make check     # local ruff + mypy + pytest
make demo      # offline pipeline; expected run exit 1 is ignored by Make
```

## The rules that matter

**A capability lands on `HarnessService` before it lands on the MCP gateway.**
Otherwise non-MCP callers cannot reuse it, and you have created a Claude-only
code path that escapes the ordinary review that CI applies. Add explicit CLI
wiring when the operation should also be user-facing there.

**No language model in the verdict.** `resolve_verdict` and the four axis
functions are pure. If a change would make a verdict depend on a model, a clock or
the network, it belongs somewhere else. See
[ADR 0002](docs/adr/0002-deterministic-verdict.md).

**No generic-capability tools.** No shell, SQL, arbitrary URL or arbitrary prompt
on the MCP surface. `tests/test_mcp_contract.py` enforces this, so the build will
tell you before a reviewer does. See
[ADR 0003](docs/adr/0003-constrained-mcp-tools.md).

**An uncollectable source is an `error`, never a `pass`.** This is the most
dangerous bug available to this kind of tool: the evidence pipeline breaks, every
assertion finds nothing, every `must_not` passes, and the dashboard turns green at
exactly the moment it should be screaming.

## Adding a scenario

1. Copy the closest existing file in `scenarios/`.
2. `agentsec validate --scenario <id> --target <target> --strict`.
3. Write all four axes. Treat a `red_only` warning as an error — a scenario that
   only checks prevention cannot distinguish a fix from a silent bypass.
4. Add a fixture set under `fixtures/<target>/` so it runs offline.
5. Start at `gate: warning`. Promote to `blocking` after a week of stable nightlies.

## Adding an evidence collector

Write `src/agentsec/evidence/<name>.py` normalising into
`schemas/evidence.schema.json`, add a backend to `schemas/target.schema.json` and
`models/target.py`, and wire it into `evidence/collector.py`. Raise
`EvidenceUnavailable` on failure — the orchestrator turns that into a
`CollectorError`, and the axis degrades to `error`.

You should not need to touch the evaluator. If you do, the normalisation is
leaking vendor detail.

## Commit messages

Explain the reasoning, not the diff. `feat(evidence): rebase fixture timelines
into the run window` beats `update wazuh.py`.
