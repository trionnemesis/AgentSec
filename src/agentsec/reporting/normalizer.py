"""Report normalisation.

Every output format — JUnit for CI, HTML for humans, JSON for the dashboard and
the MCP resources — is rendered from this one shape. Adding a fifth output means
writing a renderer, not re-deriving what a run "means" for a fifth time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from agentsec.models.run import AxisStatus, PurpleVerdict, Run
from agentsec.models.scenario import Scenario
from agentsec.policy.profiles import Profile


@dataclass
class RunSummary:
    run_id: str
    scenario_id: str
    scenario_title: str
    severity: str
    target_id: str
    profile: str
    status: str
    verdict: str
    prevention: str
    detection: str
    evidence: str
    response: str
    rationale: str
    duration_seconds: float
    created_at: str
    blocking: bool
    gate: str
    failed_checks: list[dict[str, Any]] = field(default_factory=list)
    collector_errors: list[dict[str, str]] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "scenario_title": self.scenario_title,
            "severity": self.severity,
            "target_id": self.target_id,
            "profile": self.profile,
            "status": self.status,
            "purple_verdict": self.verdict,
            "prevention": self.prevention,
            "detection": self.detection,
            "evidence": self.evidence,
            "response": self.response,
            "rationale": self.rationale,
            "duration_seconds": self.duration_seconds,
            "created_at": self.created_at,
            "blocking": self.blocking,
            "gate": self.gate,
            "failed_checks": self.failed_checks,
            "collector_errors": self.collector_errors,
            "owasp": self.owasp,
            "tags": self.tags,
        }


def normalize_run(
    run: Run,
    scenario: Scenario | None = None,
    profile: Profile | None = None,
    collector_errors: list[dict[str, str]] | None = None,
) -> RunSummary:
    verdict = run.verdict
    duration = 0.0
    if run.started_at and run.finished_at:
        duration = round((run.finished_at - run.started_at).total_seconds(), 3)

    gate = scenario.spec.regression.gate if scenario else "warning"
    verdict_enum = verdict.purple_verdict if verdict else PurpleVerdict.ERROR
    blocking = bool(
        gate == "blocking" and profile is not None and profile.blocks(verdict_enum)
    )

    failed = []
    if verdict:
        for axis in verdict.axes:
            for check in axis.checks:
                if check.status in (AxisStatus.FAIL, AxisStatus.ERROR):
                    failed.append(
                        {
                            "id": check.id,
                            "axis": check.axis,
                            "status": str(check.status),
                            "assertion": check.assertion,
                            "observed": check.observed or "",
                            "reason": check.reason or "",
                        }
                    )

    return RunSummary(
        run_id=run.run_id,
        scenario_id=run.scenario_id,
        scenario_title=scenario.metadata.title if scenario else run.scenario_id,
        severity=str(scenario.metadata.severity) if scenario else "info",
        target_id=run.target_id,
        profile=run.profile,
        status=str(run.status),
        verdict=str(verdict_enum),
        prevention=str(verdict.prevention) if verdict else "error",
        detection=str(verdict.detection) if verdict else "error",
        evidence=str(verdict.evidence) if verdict else "error",
        response=str(verdict.response) if verdict else "error",
        rationale=(verdict.rationale if verdict else run.refusal_reason) or "",
        duration_seconds=duration,
        created_at=run.created_at.isoformat(),
        blocking=blocking,
        gate=gate,
        failed_checks=failed,
        collector_errors=collector_errors or [],
        owasp=list(scenario.metadata.references.owasp_agentic) if scenario else [],
        tags=list(scenario.metadata.tags) if scenario else [],
    )


def latest_per_scenario(summaries: list[RunSummary]) -> list[RunSummary]:
    """Keep only the most recent summary per (scenario, target).

    A rollup over every stored run measures how often CI ran, not how many
    problems exist: four scenarios run twice would report eight runs, four of them
    ``secure``, and name each blocking scenario twice. ``ResultStore.verdict_counts``
    already dedupes for exactly this reason, and a report that does not is the same
    database disagreeing with itself.

    Ties on ``created_at`` are broken by ``run_id``, which is sequential within the
    day — a whole batch can share a timestamp to the second.
    """
    ordered = sorted(summaries, key=lambda s: (s.created_at, s.run_id), reverse=True)
    seen: set[tuple[str, str]] = set()
    latest: list[RunSummary] = []
    for summary in ordered:
        key = (summary.scenario_id, summary.target_id)
        if key in seen:
            continue
        seen.add(key)
        latest.append(summary)
    return latest


def verdict_history(
    summaries: list[RunSummary], *, per_scenario: int = 10
) -> dict[str, list[dict[str, str]]]:
    """Per-scenario verdict timeline, oldest first.

    The rollup deliberately reports only the latest run per scenario, which answers
    "where does this target stand now" and says nothing about whether it is getting
    better. This is the other half: enough history for a reader to see a scenario
    that has been red for a week, without letting it distort today's counts.
    """
    ordered = sorted(summaries, key=lambda s: (s.created_at, s.run_id))
    history: dict[str, list[dict[str, str]]] = {}
    for summary in ordered:
        history.setdefault(summary.scenario_id, []).append(
            {
                "run_id": summary.run_id,
                "verdict": summary.verdict,
                "created_at": summary.created_at,
                "profile": summary.profile,
            }
        )
    return {sid: runs[-per_scenario:] for sid, runs in history.items()}


def normalize_batch(summaries: list[RunSummary], *, profile: str, target_id: str) -> dict[str, Any]:
    """Batch-level rollup, including the CI exit decision.

    Callers pass the runs they want counted. ``start_run`` runs each scenario once,
    so its list is already one-per-scenario; ``generate_report`` reads history out
    of the store and narrows it with ``latest_per_scenario`` first.
    """
    counts: dict[str, int] = {}
    for s in summaries:
        counts[s.verdict] = counts.get(s.verdict, 0) + 1

    axis_counts = {
        axis: {
            status: sum(1 for s in summaries if getattr(s, axis) == status)
            for status in ("pass", "fail", "not_tested", "error")
        }
        for axis in ("prevention", "detection", "evidence", "response")
    }

    blocking = [s for s in summaries if s.blocking]

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "profile": profile,
        "target_id": target_id,
        "total_runs": len(summaries),
        "verdict_counts": counts,
        "axis_counts": axis_counts,
        "secure": counts.get("secure", 0),
        "blocking_count": len(blocking),
        "blocking_scenarios": [s.scenario_id for s in blocking],
        "exit_code": 1 if blocking else 0,
        "runs": [s.to_dict() for s in summaries],
    }
