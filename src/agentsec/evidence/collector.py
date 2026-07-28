"""Evidence orchestration.

Collects only the sources the scenario's contract actually asserts on, and
records every collector failure rather than swallowing it. A source that could
not be collected degrades its axis to ``error`` — never to ``pass``. Silent
degradation to green is the single most dangerous bug a purple harness can have.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

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
    def __init__(self, workspace: Path) -> None:
        self._workspace = workspace

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
        window_end = window_end or datetime.now(UTC)
        ctx = CollectContext(
            run_id=run_id,
            scenario_id=scenario.id,
            target=target,
            workspace=self._workspace,
            window_start=window_start,
            window_end=window_end,
        )

        sources = EvidenceSources(transcript=transcript)
        errors: list[CollectorError] = []

        collectors = {
            "wazuh": collect_wazuh,
            "otel": collect_otel,
            "tool_audit": collect_tool_audit,
            "state_diff": collect_state_diff,
        }

        for name in sorted(self.required_sources(scenario)):
            try:
                setattr(sources, name, collectors[name](ctx))
            except AgentSecError as exc:
                errors.append(CollectorError(source=name, message=exc.message))
            except Exception as exc:  # a collector bug must not lose the run
                errors.append(
                    CollectorError(source=name, message=f"{type(exc).__name__}: {exc}")
                )

        return Evidence(
            run_id=run_id,
            collected_at=datetime.now(UTC),
            window=EvidenceWindow(start=window_start, end=window_end),
            sources=sources,
            collector_errors=errors,
        )
