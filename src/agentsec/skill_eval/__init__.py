"""Deterministic static assurance for reviewed agent skill assets.

This is the Phase 0 half of ADR 0008.  It deliberately exports no runner,
verdict, store or MCP adapter: structural integrity is useful before any model
is invoked, and must not be presented as evidence that a skill behaved.
"""

from agentsec.skill_eval.static import StaticReport, validate_static

__all__ = ["StaticReport", "validate_static"]
