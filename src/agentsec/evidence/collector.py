"""Evidence orchestration.

Collects only the sources the scenario's contract actually asserts on, and
records every collector failure rather than swallowing it. A source that could
not be collected degrades its axis to ``error`` — never to ``pass``. Silent
degradation to green is the single most dangerous bug a purple harness can have.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from agentsec.errors import AgentSecError
from agentsec.evidence.base import CollectContext
from agentsec.evidence.otel import collect_otel
from agentsec.evidence.state_diff import collect_state_diff
from agentsec.evidence.tool_audit import collect_tool_audit
from agentsec.evidence.wazuh import collect_wazuh
from agentsec.models.evidence import (
    CollectorError,
    Evidence,
    EvidenceSources,
    EvidenceWindow,
    TranscriptSource,
)
from agentsec.models.scenario import Scenario
from agentsec.models.target import Target


class EvidenceCollector:
    def __init__(
        self,
        workspace: Path,
        *,
        clock: Callable[[], datetime] | None = None,
        sleeper: Callable[[float], None] | None = None,
        poll_interval_seconds: float = 1.0,
        telemetry_settle_seconds: float = 5.0,
    ) -> None:
        self._workspace = workspace
        self._clock = clock or (lambda: datetime.now(UTC))
        self._sleeper = sleeper or time.sleep
        self._poll_interval_seconds = max(0.0, poll_interval_seconds)
        self._telemetry_settle_seconds = max(0.0, telemetry_settle_seconds)

    @staticmethod
    def required_sources(scenario: Scenario) -> set[str]:
        """Which evidence sources this scenario's contract depends on."""
        needed: set[str] = set()
        contract = scenario.spec.contract

        if contract.detection:
            if contract.detection.wazuh:
                needed.add("wazuh")
            if contract.detection.otel:
                needed.add("otel")
        if contract.evidence:
            if contract.evidence.otel:
                needed.add("otel")
            if contract.evidence.tool_audit:
                needed.add("tool_audit")
            if contract.evidence.state_diff:
                needed.add("state_diff")
        if contract.prevention:
            # Prevention reads tool calls and policy decisions out of the audit
            # log, and output assertions out of the transcript.
            for assertion in [*contract.prevention.must, *contract.prevention.must_not]:
                if assertion.kind in {"tool_call", "policy_decision"}:
                    needed.add("tool_audit")
                elif assertion.kind == "state_change":
                    needed.add("state_diff")
                elif assertion.kind == "http_egress":
                    needed.add("otel")
        if contract.response and contract.response.mode != "not_tested":
            needed.add("tool_audit")
            if contract.response.expected_actions:
                # Automated responses may be emitted as agentsec.response.*
                # spans; collect both supported representations and evaluate
                # them against their own event timestamps.
                needed.add("otel")

        return needed

    def collect(
        self,
        *,
        run_id: str,
        scenario: Scenario,
        target: Target,
        transcript: TranscriptSource,
        window_start: datetime,
        window_end: datetime | None = None,
    ) -> Evidence:
        collectors = {
            "wazuh": collect_wazuh,
            "otel": collect_otel,
            "tool_audit": collect_tool_audit,
            "state_diff": collect_state_diff,
        }
        required = sorted(self.required_sources(scenario))
        contractual_seconds = _max_contractual_deadline(scenario)
        settle_seconds = max(self._telemetry_settle_seconds, contractual_seconds)
        stop_at = window_end or (window_start + timedelta(seconds=settle_seconds))
        latest: Evidence | None = None

        # A source outage is terminal. Retrying it as if the assertion were
        # merely undecidable would turn an unavailable backend into a gap.
        while True:
            observed_end = self._clock()
            if observed_end < window_start:
                observed_end = window_start
            if window_end is not None and observed_end > window_end:
                observed_end = window_end
            ctx = CollectContext(
                run_id=run_id,
                scenario_id=scenario.id,
                target=target,
                workspace=self._workspace,
                window_start=window_start,
                window_end=observed_end,
                trusted_fixture=target.adapter.kind == "fixture",
            )

            sources = EvidenceSources(transcript=transcript)
            errors: list[CollectorError] = []
            for name in required:
                try:
                    setattr(sources, name, collectors[name](ctx))
                except AgentSecError as exc:
                    errors.append(CollectorError(source=name, message=exc.message))
                except Exception as exc:  # a collector bug must not lose the run
                    errors.append(
                        CollectorError(source=name, message=f"{type(exc).__name__}: {exc}")
                    )

            latest = Evidence(
                run_id=run_id,
                collected_at=observed_end,
                window=EvidenceWindow(start=window_start, end=observed_end),
                sources=sources,
                collector_errors=errors,
            )
            if errors or _assertions_decidable(scenario, latest, observed_end, stop_at):
                return latest
            # Recorded fixtures are immutable snapshots, not a delayed live
            # backend.  Their explicit trusted-context normalisation preserves
            # the historical verdict matrix without sleeping through an SLA.
            if ctx.trusted_fixture:
                return latest
            if observed_end >= stop_at:
                return latest

            remaining = (stop_at - observed_end).total_seconds()
            delay = min(self._poll_interval_seconds, max(0.0, remaining))
            if delay <= 0:
                return latest
            self._sleeper(delay)


def _max_contractual_deadline(scenario: Scenario) -> float:
    """Maximum assertion SLA; executor timeout is intentionally not included."""
    contract = scenario.spec.contract
    deadlines: list[int] = []
    if contract.detection:
        if contract.detection.wazuh:
            deadlines.extend(
                a.within_seconds
                for a in [
                    *contract.detection.wazuh.must_fire,
                    *contract.detection.wazuh.must_not_fire,
                ]
            )
        # OTel SpanAssertion has no latency field; use the longest detection SLA
        # when a trace is the required source for that contract.
        if contract.detection.otel:
            # SpanAssertion predates per-span SLAs.  Keep a bounded settle
            # window for that source without coupling it to attack execution.
            deadlines.append(300)
    if contract.response:
        deadlines.extend(a.within_seconds for a in contract.response.expected_actions)
    return float(max(deadlines, default=0))


def _assertions_decidable(
    scenario: Scenario, evidence: Evidence, now: datetime, stop_at: datetime
) -> bool:
    """Return true only when required evidence is complete or its SLA elapsed."""
    from agentsec.evaluation import matchers as m

    contract = scenario.spec.contract
    window_start = evidence.window.start if evidence.window else now
    if contract.prevention and any(
        not _prevention_assertion_decidable(assertion, evidence)
        for assertion in [*contract.prevention.must, *contract.prevention.must_not]
    ) and now < stop_at:
        return False
    if contract.detection:
        if contract.detection.wazuh:
            if any(
                not m.find_alerts(evidence, assertion, window_start=window_start)
                for assertion in contract.detection.wazuh.must_fire
            ):
                return False
            if contract.detection.wazuh.must_not_fire and now < stop_at:
                return False
        if contract.detection.otel and any(
            m.count_spans(evidence, assertion) < assertion.min_count
            for assertion in contract.detection.otel.must_emit
        ):
            return False

    if contract.evidence:
        if contract.evidence.otel and any(
            m.count_spans(evidence, assertion) < assertion.min_count
            for assertion in contract.evidence.otel.required_spans
        ):
            return False
        if contract.evidence.tool_audit and any(
            m.count_tool_records(evidence, assertion) < assertion.min_count
            for assertion in contract.evidence.tool_audit.required_records
        ):
            return False
        state = contract.evidence.state_diff
        if state and (
            state.must_be_empty is not None
            or state.allowed_changes
            or state.forbidden_changes
        ) and now < stop_at:
            return False
        if contract.evidence.tool_audit and contract.evidence.tool_audit.every_tool_call_audited:
            from agentsec.evaluation.axes import _every_tool_call_audited_check

            audit_check = _every_tool_call_audited_check(scenario, evidence)
            if audit_check.status.value != "pass" and now < stop_at:
                return False

    return not (
        contract.response
        and contract.response.expected_actions
        and any(
            not _response_action_present(evidence, action.action)
            for action in contract.response.expected_actions
        )
    )


def _prevention_assertion_decidable(assertion: Any, evidence: Evidence) -> bool:
    """A negative result needs the settle/deadline boundary, not an empty poll."""
    from agentsec.evaluation import matchers as m

    if assertion.kind in {"output_contains", "output_matches"}:
        return evidence.sources.transcript is not None
    if assertion.kind in {"tool_call", "policy_decision"}:
        records = m.tool_records(evidence)
        if assertion.kind == "tool_call":
            records = [
                record for record in records
                if (assertion.tool is None or record.tool == assertion.tool)
                and (
                    assertion.as_principal is None
                    or record.principal == assertion.as_principal
                )
            ]
            wanted = assertion.decision or "allow"
            return any(record.decision == wanted for record in records)
        return any(
            assertion.decision is None or record.decision == assertion.decision
            for record in records
        )
    if assertion.kind == "state_change":
        return any(
            assertion.resource is None or change.collection == assertion.resource
            for change in m.state_changes(evidence)
        )
    if assertion.kind == "http_egress":
        return any(
            assertion.resource is not None
            and any(
                key in span.attributes and assertion.resource in str(span.attributes[key])
                for key in ("http.url", "url.full", "server.address", "net.peer.name")
            )
            for span in m.spans(evidence)
        )
    return True


def _response_action_present(evidence: Evidence, action: str) -> bool:
    audit_seen = bool(
        evidence.sources.tool_audit
        and any(
            record.tool == action and record.decision == "allow"
            for record in evidence.sources.tool_audit.records
        )
    )
    otel_seen = bool(
        evidence.sources.otel
        and any(
            span.name == f"agentsec.response.{action}"
            for span in evidence.sources.otel.spans
        )
    )
    return audit_seen or otel_seen
