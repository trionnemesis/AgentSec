"""Executor registry.

``pyrit`` and ``pytest`` are declared but not implemented. They resolve to a
stub that refuses cleanly, so a scenario referencing them fails with
"executor not implemented" instead of "unknown executor" — the difference
matters when you are reading a coverage report and deciding what to build next.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from agentsec.errors import ExecutorUnavailable
from agentsec.execution.base import ExecutionContext, RedExecutor, make_result
from agentsec.execution.promptfoo import PromptfooExecutor
from agentsec.execution.replay import ReplayExecutor
from agentsec.models.evidence import TranscriptSource
from agentsec.models.run import ExecutionResult
from agentsec.models.target import Target


class NotImplementedExecutor:
    def __init__(self, name: str, note: str) -> None:
        self.name = name
        self._note = note

    def available(self, target: Target) -> tuple[bool, str]:
        return False, self._note

    def execute(self, ctx: ExecutionContext) -> tuple[ExecutionResult, TranscriptSource]:
        return (
            make_result(self.name, datetime.now(UTC), ok=False, error=self._note),
            TranscriptSource(),
        )


_PLANNED = {
    "pyrit": "PyRIT executor is planned but not implemented (see docs/roadmap.md)",
    "pytest": "pytest executor is planned but not implemented (see docs/roadmap.md)",
}


def get_executor(name: str, workspace: Path) -> RedExecutor:
    if name == "replay":
        return ReplayExecutor(workspace)
    if name == "promptfoo":
        return PromptfooExecutor(workspace)
    if name in _PLANNED:
        return NotImplementedExecutor(name, _PLANNED[name])
    raise ExecutorUnavailable(
        f"unknown executor '{name}'",
        details={"known": ["replay", "promptfoo", *sorted(_PLANNED)]},
    )


def available_executors(target: Target, workspace: Path) -> dict[str, str]:
    """Map executor name -> readiness reason, for preview_run and diagnostics."""
    out: dict[str, str] = {}
    for name in ("replay", "promptfoo", *sorted(_PLANNED)):
        ok, reason = get_executor(name, workspace).available(target)
        out[name] = "ready" if ok else reason
    return out
