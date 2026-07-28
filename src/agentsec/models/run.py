"""Run, per-axis results and the Purple Verdict.

The verdict is a pure function of (contract, evidence). No model output, no
heuristic scoring, no "the LLM said it looked fine". That property is what lets
CI depend on it.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AxisStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    NOT_TESTED = "not_tested"
    ERROR = "error"


class PurpleVerdict(StrEnum):
    """Overall outcome, in precedence order (worst first).

    ``detection_gap`` deliberately outranks ``prevention_gap``: a control that
    fails loudly is recoverable, a control that fails silently is not. If an
    attack succeeded *and* nobody saw it, the detection gap is the finding you
    must fix first, so it is the one the verdict names.
    """

    ERROR = "error"
    DETECTION_GAP = "detection_gap"
    PREVENTION_GAP = "prevention_gap"
    EVIDENCE_GAP = "evidence_gap"
    RESPONSE_GAP = "response_gap"
    SECURE = "secure"


#: Ordered worst -> best. Used by the verdict resolver and by CI gating.
VERDICT_PRECEDENCE: tuple[PurpleVerdict, ...] = (
    PurpleVerdict.ERROR,
    PurpleVerdict.DETECTION_GAP,
    PurpleVerdict.PREVENTION_GAP,
    PurpleVerdict.EVIDENCE_GAP,
    PurpleVerdict.RESPONSE_GAP,
    PurpleVerdict.SECURE,
)


class RunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    REFUSED = "refused"
    """Policy declined to start the run. Distinct from FAILED: nothing executed."""


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CheckResult(_Base):
    """One assertion from the contract, checked against the evidence."""

    id: str
    axis: Literal["prevention", "detection", "evidence", "response"]
    assertion: str
    """Human-readable rendering of the contract assertion."""
    status: AxisStatus
    observed: str | None = None
    reason: str | None = None
    """The scenario author's rationale, carried through to the finding."""


class AxisResult(_Base):
    axis: Literal["prevention", "detection", "evidence", "response"]
    status: AxisStatus
    checks: list[CheckResult] = Field(default_factory=list)
    summary: str | None = None

    @property
    def failed_checks(self) -> list[CheckResult]:
        return [c for c in self.checks if c.status is AxisStatus.FAIL]


class Verdict(_Base):
    purple_verdict: PurpleVerdict
    prevention: AxisStatus
    detection: AxisStatus
    evidence: AxisStatus
    response: AxisStatus
    axes: list[AxisResult] = Field(default_factory=list)
    rationale: str = ""

    def axis(self, name: str) -> AxisResult | None:
        for a in self.axes:
            if a.axis == name:
                return a
        return None

    @property
    def is_secure(self) -> bool:
        return self.purple_verdict is PurpleVerdict.SECURE


class ExecutionResult(_Base):
    """What the red executor did. Deliberately separate from the verdict:
    a successful execution that proves a control is broken is not a failure."""

    executor: str
    started_at: datetime
    finished_at: datetime
    ok: bool
    """True if the attack ran to completion. False means we could not test."""
    steps_completed: list[str] = Field(default_factory=list)
    error: str | None = None
    raw_ref: str | None = None
    """Path to the raw executor output kept out of the DB (promptfoo json, etc)."""


class Run(_Base):
    run_id: str
    scenario_id: str
    target_id: str
    profile: str
    status: RunStatus
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    dry_run: bool = False
    execution: ExecutionResult | None = None
    verdict: Verdict | None = None
    evidence_ref: str | None = None
    refusal_reason: str | None = None
    initiated_by: str = "cli"
    approval_id: str | None = None
    scenario_digest: str | None = None
    """SHA-256 of the canonicalised scenario, so a result can be tied to the exact
    contract that produced it even after the YAML is edited."""
