"""A risk raised against this repository's own agent configuration.

The distinction this module is built around, and the reason it does not reuse
``PurpleVerdict``: **a risk is a reason to test, not a result.** Everything here
comes from reading files statically. Nothing here has been executed, nothing has
been observed, and no blue-team control has been given the chance to notice
anything. Calling that a verdict would be the exact failure
[ADR 0002](../../../docs/adr/0002-deterministic-verdict.md) exists to prevent,
one level further upstream.

So a risk carries its own vocabulary:

``severity``
    How bad it would be *if* it were real. Rule-authored, fixed per rule, never
    inferred from the repository.

``verification``
    Whether anything in the catalogue can turn this into a deterministic
    conclusion, and whether it has. This is the handoff to the Purple Harness,
    and it fails closed: the default is ``not_verifiable``, which reads as "we
    cannot prove this either way", never as a pass.

``evidence``
    Bounded facts a rule derived — counts, line numbers, Unicode codepoint
    names, the name of a construct. Never file content. Discovery holds the
    line that values stay behind so its output needs no second redaction pass
    (``project/discovery.py``), and a risk plane that quoted the offending line
    would hand that property straight back.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from agentsec.models.posture import Severity

#: Ordered worst-first, which is the order a reader needs and the order the
#: `scan` command sorts by.
SEVERITY_ORDER: tuple[Severity, ...] = ("critical", "high", "medium", "low", "info")

#: Which severities are worth handing to the harness by default. A `medium`
#: risk is still reported; it just does not, on its own, justify spending a run.
VERIFY_SEVERITIES: frozenset[Severity] = frozenset({"critical", "high"})

VerificationState = Literal["verified", "verifiable", "not_verifiable"]
"""
``verified``
    A scenario declaring this surface has actually produced a verdict. The
    Purple planes hold the conclusion; this plane only points at it.
``verifiable``
    Such a scenario exists in the catalogue but has never run here. This is the
    queue `agentsec scan --verify` drains.
``not_verifiable``
    Nothing in the catalogue exercises this surface. The honest state for most
    risks today, and the one that must never be rendered as green — it means
    the static rule is all anyone has.
"""


class Verification(BaseModel):
    """The bridge from a static risk to a deterministic conclusion."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: VerificationState = "not_verifiable"
    scenario_ids: list[str] = Field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "scenario_ids": list(self.scenario_ids),
            "detail": self.detail,
        }


class RepoRisk(BaseModel):
    """One rule firing against one surface.

    ``id`` is stable across runs of the same commit — rule id plus surface path
    — so a dashboard can diff two scans without the rows shuffling, and so a
    risk that was present yesterday and is absent today is visibly the *same*
    risk having gone away.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    severity: Severity
    surface_kind: str
    surface_id: str
    file: str
    title: str
    detail: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    verification: Verification = Field(default_factory=Verification)

    @property
    def id(self) -> str:
        return f"{self.rule_id}:{self.file}"

    @property
    def should_verify(self) -> bool:
        """High enough to be worth a run, and something can actually run it."""
        return self.severity in VERIFY_SEVERITIES and self.verification.state == "verifiable"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "surface_kind": self.surface_kind,
            "surface_id": self.surface_id,
            "file": self.file,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "verification": self.verification.to_dict(),
        }


def severity_counts(risks: list[RepoRisk]) -> dict[str, int]:
    return {level: sum(1 for r in risks if r.severity == level) for level in SEVERITY_ORDER}


def verification_counts(risks: list[RepoRisk]) -> dict[str, int]:
    states: tuple[VerificationState, ...] = ("verified", "verifiable", "not_verifiable")
    return {state: sum(1 for r in risks if r.verification.state == state) for state in states}


def sort_key(risk: RepoRisk) -> tuple[int, str, str]:
    """Worst first, then stable by rule and path."""
    return (SEVERITY_ORDER.index(risk.severity), risk.rule_id, risk.file)
