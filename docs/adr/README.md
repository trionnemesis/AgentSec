# Architecture Decision Records

Each ADR records a decision, the alternatives that were rejected, and the cost
accepted. The rejected alternatives are the useful part: they are what stops the
same debate being reopened in six months without new information.

| # | Decision | Status |
|---|---|---|
| [0001](0001-four-layer-separation.md) | Four layers, with a hard service boundary | Accepted |
| [0002](0002-deterministic-verdict.md) | No LLM in the pass/fail decision | Accepted |
| [0003](0003-constrained-mcp-tools.md) | No generic-capability MCP tools | Accepted |
| [0004](0004-detection-outranks-prevention.md) | `detection_gap` outranks `prevention_gap` | Accepted |
| [0005](0005-local-first-deployment.md) | Local MCP first, remote gateway later | Accepted |
| [0006](0006-normalised-evidence-schema.md) | Normalise evidence, don't query vendors from the evaluator | Accepted |
| [0007](0007-sqlite-and-files.md) | SQLite plus JSON files, not a service database | Accepted |
| [0008](0008-skill-assurance-bounded-context.md) | Skill Assurance is a separate bounded context | Accepted |
