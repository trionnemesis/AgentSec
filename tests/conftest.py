"""Test fixtures.

Each test gets an isolated workspace copied from the repository's real
scenarios/policy/fixtures. Copying rather than mocking means the tests exercise
the same catalogue and allowlist that ship, so a broken scenario YAML fails the
build.
"""

from __future__ import annotations

import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentsec.config import Settings
from agentsec.models.evidence import (
    Evidence,
    EvidenceSources,
    EvidenceWindow,
    OtelSource,
    OtelSpan,
    ToolAuditRecord,
    ToolAuditSource,
    TranscriptSource,
    TranscriptTurn,
    WazuhAlert,
    WazuhSource,
)
from agentsec.service.harness import HarnessService

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    for name in ("scenarios", "policy", "fixtures"):
        shutil.copytree(REPO_ROOT / name, tmp_path / name)
    return tmp_path


@pytest.fixture
def settings(workspace: Path) -> Settings:
    s = Settings(
        workspace=workspace,
        scenarios_dir=workspace / "scenarios",
        policy_dir=workspace / "policy",
        results_dir=workspace / "results",
        db_path=workspace / "results" / "agentsec.db",
        actor="pytest",
    )
    s.ensure_dirs()
    return s


@pytest.fixture
def service(settings: Settings) -> HarnessService:
    return HarnessService(settings, actor="pytest")


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 7, 28, 9, 0, 0, tzinfo=UTC)


def make_evidence(
    *,
    run_id: str = "RUN-20260728-001",
    window_start: datetime | None = None,
    turns: list[TranscriptTurn] | None = None,
    spans: list[OtelSpan] | None = None,
    alerts: list[WazuhAlert] | None = None,
    records: list[ToolAuditRecord] | None = None,
    state_changes: list | None = None,
    collector_errors: list | None = None,
) -> Evidence:
    """Hand-build an evidence bundle for axis-level unit tests."""
    start = window_start or datetime(2026, 7, 28, 9, 0, 0, tzinfo=UTC)
    correlated_spans = (
        [
            span
            if span.run_id is not None
            else span.model_copy(update={"run_id": run_id})
            for span in spans
        ]
        if spans is not None
        else None
    )
    correlated_alerts = (
        [
            alert
            if alert.run_id is not None
            else alert.model_copy(update={"run_id": run_id})
            for alert in alerts
        ]
        if alerts is not None
        else None
    )
    correlated_records = (
        [
            record
            if record.run_id is not None
            else record.model_copy(update={"run_id": run_id})
            for record in records
        ]
        if records is not None
        else None
    )
    sources = EvidenceSources(
        transcript=TranscriptSource(turns=turns or []),
        otel=OtelSource(spans=correlated_spans) if correlated_spans is not None else None,
        wazuh=WazuhSource(alerts=correlated_alerts)
        if correlated_alerts is not None
        else None,
        tool_audit=ToolAuditSource(records=correlated_records)
        if correlated_records is not None
        else None,
    )
    if state_changes is not None:
        from agentsec.models.evidence import StateDiffSource

        sources.state_diff = StateDiffSource(changes=state_changes)

    return Evidence(
        run_id=run_id,
        collected_at=start + timedelta(seconds=10),
        window=EvidenceWindow(start=start, end=start + timedelta(seconds=60)),
        sources=sources,
        collector_errors=collector_errors or [],
    )
