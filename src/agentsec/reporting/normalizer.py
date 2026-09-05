"""Report normalisation.

Every output format — JUnit for CI, HTML for humans, JSON for the dashboard and
the MCP resources — is rendered from this one shape. Adding a fifth output means
writing a renderer, not re-deriving what a run "means" for a fifth time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from agentsec.errors import EvidenceUnavailable
from agentsec.evidence.base import canonical_run_id
from agentsec.models.evidence import (
    Evidence,
    OtelSource,
    StateDiffSource,
    ToolAuditSource,
    WazuhSource,
)
from agentsec.models.run import AxisStatus, PurpleVerdict, Run, RunStatus
from agentsec.models.scenario import Scenario
from agentsec.models.target import Target
from agentsec.policy.profiles import Profile
from agentsec.reporting.publish import PUBLISH_SCHEMA_VERSION

EvidenceProvenance = Literal["recorded", "live", "mixed"]

@dataclass
class Provenance:
    """How a run's evidence was actually produced — never how it was judged.

    Presentation only: adding this changes no verdict and no axis (ADR 0002 is
    unamended). A ``secure`` produced entirely from replayed fixtures is still
    ``secure``; this just says what it was proven against, the same way
    AgentShield's ``runtimeConfidence`` tags a finding without changing its rule.
    """

    executor: str
    adapter: str
    evidence: EvidenceProvenance
    backends: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "executor": self.executor,
            "adapter": self.adapter,
            "evidence": self.evidence,
            "backends": dict(self.backends),
        }


def _aware(timestamp: datetime | None) -> bool:
    return timestamp is not None and timestamp.utcoffset() is not None


def _source_is_live(
    source: OtelSource | WazuhSource | ToolAuditSource | StateDiffSource,
    evidence: Evidence,
) -> bool:
    """Qualify presentation only; do not repair records or re-evaluate a verdict."""
    if source.meta is None or source.meta.correlation != "verified":
        return False
    bags: list[dict[str, Any]] = []
    if isinstance(source, OtelSource):
        bags = [span.attributes for span in source.spans]
    elif isinstance(source, WazuhSource):
        bags = [alert.fields for alert in source.alerts]
    try:
        if any(canonical_run_id(bag) not in (None, evidence.run_id) for bag in bags):
            return False
    except EvidenceUnavailable:
        return False
    observations: list[tuple[str | None, datetime | None]]
    if isinstance(source, OtelSource):
        observations = [(span.run_id, span.start_time) for span in source.spans]
    elif isinstance(source, WazuhSource):
        observations = [(alert.run_id, alert.timestamp) for alert in source.alerts]
    elif isinstance(source, ToolAuditSource):
        observations = [(record.run_id, record.timestamp) for record in source.records]
    else:
        # State diffs have no per-record correlation/time contract today.
        return False
    window = evidence.window
    if not observations or window is None or not all(
        _aware(t) for t in (window.start, window.end, evidence.collected_at)
    ):
        return False
    end = min(window.end, evidence.collected_at)
    if window.start > end:
        return False
    return all(
        run_id == evidence.run_id
        and timestamp is not None
        and _aware(timestamp)
        and window.start <= timestamp <= end
        for run_id, timestamp in observations
    )


def derive_provenance(
    run: Run,
    target: Target | None = None,
    evidence_backends: dict[str, str] | None = None,
    evidence: Evidence | None = None,
) -> Provenance:
    """Use persisted correlation/time evidence, with a conservative fallback.

    Backend kinds remain diagnostics; a transport never promotes a source.
    Historical reports are re-derived without rewriting stored data (ADR 0010).
    """
    backends = dict(evidence_backends or {})
    adapter: str = target.adapter.kind if target is not None else "unknown"
    origins: set[str] = set()
    if evidence is not None and evidence.run_id == run.run_id:
        errors = {error.source for error in evidence.collector_errors}
        backends = {}
        executed = (
            run.execution is not None and not run.dry_run
            and run.status not in {RunStatus.PENDING, RunStatus.REFUSED}
        )
        transcript = evidence.sources.transcript
        if transcript is not None:
            # The current allowlist is mutable; the stored adapter is not.
            adapter = (transcript.meta.backend if transcript.meta else None) or "unknown"
            if (
                executed and run.execution is not None and run.execution.ok
                and transcript.turns and "transcript" not in errors
            ):
                origins.add("live" if adapter == "http" else "recorded")
        for name in ("otel", "wazuh", "tool_audit", "state_diff"):
            source = getattr(evidence.sources, name)
            if source is None or name in errors:
                continue
            if source.meta is not None and source.meta.backend:
                backends[name] = source.meta.backend
            if executed:
                origins.add("live" if _source_is_live(source, evidence) else "recorded")
    kind: EvidenceProvenance = "recorded"
    if origins == {"live"}:
        kind = "live"
    elif origins == {"live", "recorded"}:
        kind = "mixed"
    return Provenance(
        executor=run.execution.executor if run.execution else "none",
        adapter=adapter,
        evidence=kind,
        backends=backends,
    )


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
    provenance: Provenance = field(
        default_factory=lambda: Provenance(executor="none", adapter="unknown", evidence="recorded")
    )

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
            "provenance": self.provenance.to_dict(),
        }


def normalize_run(
    run: Run,
    scenario: Scenario | None = None,
    profile: Profile | None = None,
    collector_errors: list[dict[str, str]] | None = None,
    target: Target | None = None,
    evidence_backends: dict[str, str] | None = None,
    evidence: Evidence | None = None,
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
        provenance=derive_provenance(run, target, evidence_backends, evidence),
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

    provenance_counts = {
        kind: sum(1 for s in summaries if s.provenance.evidence == kind)
        for kind in ("recorded", "live", "mixed")
    }
    # The banner a reader needs: every counted verdict came from a replayed
    # fixture, not a live run. False on an empty batch — nothing has been
    # proven against anything, so there is nothing to label "fixture-derived".
    fixture_derived = bool(summaries) and provenance_counts["recorded"] == len(summaries)

    return {
        # Stamped here rather than at the gateway so the JSON written to disk
        # carries it too: a dashboard reading a file and a dashboard reading the
        # resource should not have to work out which shape they got.
        "schema_version": PUBLISH_SCHEMA_VERSION,
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
        "provenance_counts": provenance_counts,
        "fixture_derived": fixture_derived,
        "runs": [s.to_dict() for s in summaries],
    }
