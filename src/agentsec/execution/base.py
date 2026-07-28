"""Red executor interface.

An executor drives the attack and returns a transcript. It deliberately does
*not* decide whether the attack succeeded — that is the evaluator's job, against
the contract. Keeping the two apart is what stops "the runner said it passed"
from becoming the source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from agentsec.models.evidence import TranscriptSource
from agentsec.models.run import ExecutionResult
from agentsec.models.scenario import Scenario
from agentsec.models.target import Target


@dataclass(frozen=True)
class ExecutionContext:
    run_id: str
    scenario: Scenario
    scenario_path: Path | None
    target: Target
    raw_dir: Path
    timeout_seconds: int

    def raw_path(self, suffix: str) -> Path:
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        return self.raw_dir / f"{self.run_id}.{suffix}"


@runtime_checkable
class RedExecutor(Protocol):
    name: str

    def available(self, target: Target) -> tuple[bool, str]:
        """Can this executor run right now? Returns (ok, human-readable reason)."""
        ...

    def execute(self, ctx: ExecutionContext) -> tuple[ExecutionResult, TranscriptSource]:
        ...


def make_result(
    executor: str,
    started_at: datetime,
    *,
    ok: bool,
    steps_completed: list[str] | None = None,
    error: str | None = None,
    raw_ref: str | None = None,
) -> ExecutionResult:
    return ExecutionResult(
        executor=executor,
        started_at=started_at,
        finished_at=datetime.now(UTC),
        ok=ok,
        steps_completed=steps_completed or [],
        error=error,
        raw_ref=raw_ref,
    )
