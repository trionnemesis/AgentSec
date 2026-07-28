"""Purple Evaluator — combines the four axes into one verdict.

``resolve_verdict`` is the whole product in ten lines. Everything else exists to
feed it honest inputs.
"""

from __future__ import annotations

from pathlib import Path

from agentsec.evaluation.axes import (
    evaluate_detection,
    evaluate_evidence,
    evaluate_prevention,
    evaluate_response,
)
from agentsec.models.evidence import Evidence
from agentsec.models.run import AxisResult, AxisStatus, PurpleVerdict, Verdict
from agentsec.models.scenario import Scenario


def resolve_verdict(
    prevention: AxisStatus,
    detection: AxisStatus,
    evidence: AxisStatus,
    response: AxisStatus,
) -> PurpleVerdict:
    """Map four axis statuses onto one verdict, worst-first.

    Detection outranks prevention deliberately. If an attack succeeded *and*
    nothing alerted, the organisation's problem is blindness, not just a broken
    control: you can ship a fix for a control you can see failing, but you
    cannot fix what you never learn about. So the verdict names the gap you must
    close first.
    """
    if AxisStatus.ERROR in (prevention, detection, evidence, response):
        return PurpleVerdict.ERROR
    if detection is AxisStatus.FAIL:
        return PurpleVerdict.DETECTION_GAP
    if prevention is AxisStatus.FAIL:
        return PurpleVerdict.PREVENTION_GAP
    if evidence is AxisStatus.FAIL:
        return PurpleVerdict.EVIDENCE_GAP
    if response is AxisStatus.FAIL:
        return PurpleVerdict.RESPONSE_GAP
    return PurpleVerdict.SECURE


def _rationale(verdict: PurpleVerdict, axes: list[AxisResult]) -> str:
    by_axis = {a.axis: a for a in axes}

    if verdict is PurpleVerdict.SECURE:
        tested = [a.axis for a in axes if a.status is AxisStatus.PASS]
        return (
            f"all asserted axes held ({', '.join(tested)})" if tested
            else "no axis was asserted"
        )

    if verdict is PurpleVerdict.ERROR:
        broken = [a.axis for a in axes if a.status is AxisStatus.ERROR]
        return (
            f"could not evaluate {', '.join(broken)}; evidence collection failed, so "
            f"this run proves nothing either way"
        )

    headline = {
        PurpleVerdict.DETECTION_GAP: "detection",
        PurpleVerdict.PREVENTION_GAP: "prevention",
        PurpleVerdict.EVIDENCE_GAP: "evidence",
        PurpleVerdict.RESPONSE_GAP: "response",
    }[verdict]

    axis = next((a for a in axes if a.axis == headline), None)
    failures = axis.failed_checks if axis else []
    detail = "; ".join(f"{c.assertion} -> {c.observed}" for c in failures[:3])

    if verdict is PurpleVerdict.DETECTION_GAP:
        prevention_axis = by_axis.get("prevention")
        prevention_ok = (
            prevention_axis.status if prevention_axis else AxisStatus.NOT_TESTED
        )
        lead = (
            "the attack was blocked but nothing alerted on the attempt"
            if prevention_ok is AxisStatus.PASS
            else "the attack succeeded and nothing alerted"
        )
        return f"{lead}. {detail}"

    return f"{headline} failed: {detail}"


class PurpleEvaluator:
    """Stateless. Construct once, evaluate many runs."""

    def __init__(self, workspace: Path | None = None) -> None:
        self._workspace = workspace

    def evaluate(self, scenario: Scenario, evidence: Evidence) -> Verdict:
        window_start = evidence.window.start if evidence.window else None

        axes = [
            evaluate_prevention(scenario, evidence),
            evaluate_detection(scenario, evidence, window_start=window_start),
            evaluate_evidence(scenario, evidence),
            evaluate_response(scenario, evidence, workspace=self._workspace),
        ]
        by_axis = {a.axis: a.status for a in axes}

        verdict = resolve_verdict(
            by_axis["prevention"], by_axis["detection"], by_axis["evidence"], by_axis["response"]
        )

        return Verdict(
            purple_verdict=verdict,
            prevention=by_axis["prevention"],
            detection=by_axis["detection"],
            evidence=by_axis["evidence"],
            response=by_axis["response"],
            axes=axes,
            rationale=_rationale(verdict, axes),
        )

    @staticmethod
    def execution_failure_verdict(error: str) -> Verdict:
        """Verdict for a run whose attack could not be executed.

        Not ``secure``: we learned nothing. Encoding "we could not test this" as
        a pass is how coverage dashboards start lying.
        """
        axes = [
            AxisResult(
                axis=axis,  # type: ignore[arg-type]
                status=AxisStatus.ERROR,
                summary=error,
            )
            for axis in ("prevention", "detection", "evidence", "response")
        ]
        return Verdict(
            purple_verdict=PurpleVerdict.ERROR,
            prevention=AxisStatus.ERROR,
            detection=AxisStatus.ERROR,
            evidence=AxisStatus.ERROR,
            response=AxisStatus.ERROR,
            axes=axes,
            rationale=f"attack execution failed: {error}",
        )
