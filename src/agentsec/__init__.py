"""AgentSec — a purple-team harness for AI agents.

The durable asset here is not the MCP gateway or the dashboard; it is the
Attack-Detection Contract and the deterministic verdict engine behind them.
Layering, in strict order:

    Claude Code / Live Artifact   human interfaces
    -> AgentSec MCP Gateway       policy, schemas, approvals, audit
    -> HarnessService             the internal API (also used by CLI and CI)
    -> executors / collectors / evaluator / store

Nothing above the service boundary may reach below it.
"""

__version__ = "0.3.1"
__all__ = ["__version__"]
