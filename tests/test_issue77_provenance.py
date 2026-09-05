"""Issue #77: provenance must describe observed evidence, not its transport."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentsec.evidence.base import CollectContext
from agentsec.evidence.tool_audit import collect_tool_audit
from agentsec.models.evidence import Evidence, EvidenceSources, EvidenceWindow
from agentsec.models.target import Adapter, EvidenceBackends, Target, ToolAuditBackend
from agentsec.service.harness import HarnessService
from tests.test_provenance import _run


def test_live_written_file_is_live_after_collection(
    tmp_path: Path, service: HarnessService, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _run("replay")
    start = datetime.now(UTC)
    path = tmp_path / "audit.jsonl"
    path.write_text(
        '{"agentsec.run_id":"' + run.run_id + '","tool":"Read",'
        '"decision":"deny","timestamp":"' + start.isoformat() + '"}\n',
        encoding="utf-8",
    )
    target = Target(
        id=run.target_id, environment="local",
        adapter=Adapter(kind="http", base_url="http://127.0.0.1:9"),
        evidence=EvidenceBackends(tool_audit=ToolAuditBackend(kind="file", path=str(path))),
    )
    end = start + timedelta(seconds=1)
    source = collect_tool_audit(CollectContext(
        run_id=run.run_id, scenario_id=run.scenario_id, target=target,
        workspace=tmp_path, window_start=start, window_end=end,
    ))
    bundle = Evidence(
        run_id=run.run_id, collected_at=end,
        window=EvidenceWindow(start=start, end=end),
        sources=EvidenceSources(tool_audit=source),
    )
    assert source.meta is not None and source.meta.correlation == "verified"
    run.evidence_ref = service._persist_evidence(bundle)
    service.store.save_run(run)
    monkeypatch.setattr(service, "get_target", lambda _: target)
    _, summaries, _ = service._rollup(target_id=run.target_id, profile="pr", limit=10)
    assert summaries[0].provenance.evidence == "live"


def _provenance_case(source_name: str = "otel"):
    """A persisted, current-run observation with no transcript contribution."""
    run = _run("replay")
    start = datetime(2026, 9, 5, 8, 0, tzinfo=UTC)
    end = start + timedelta(seconds=10)
    run.started_at = start
    run.finished_at = end
    assert run.execution is not None
    run.execution.started_at = start
    run.execution.finished_at = end
    observations = {
        "otel": {"spans": [{
            "name": "agent.tool_call", "run_id": run.run_id, "start_time": start,
            "attributes": {"agentsec.run_id": run.run_id},
        }]},
        "wazuh": {"alerts": [{
            "rule_id": "100001", "run_id": run.run_id, "timestamp": start,
            "fields": {"agentsec.run_id": run.run_id},
        }]},
        "tool_audit": {"records": [{
            "tool": "Read", "decision": "deny", "run_id": run.run_id, "timestamp": start,
        }]},
    }
    source = observations[source_name]
    source["meta"] = {
        "collector": source_name, "backend": "file", "correlation": "verified",
    }
    bundle = Evidence.model_validate({
        "run_id": run.run_id, "collected_at": end,
        "window": {"start": start, "end": end}, "sources": {source_name: source},
    })
    return run, bundle


def _provenance_label(run, bundle) -> str:
    from agentsec.reporting.normalizer import derive_provenance

    return derive_provenance(run, evidence=bundle).evidence


@pytest.mark.parametrize("source_name", ["otel", "wazuh", "tool_audit"])
@pytest.mark.parametrize("offset", [0, 10])
def test_event_window_boundaries_are_inclusive(source_name: str, offset: int) -> None:
    run, bundle = _provenance_case(source_name)
    source = getattr(bundle.sources, source_name)
    records = getattr(source, {"otel": "spans", "wazuh": "alerts", "tool_audit": "records"}[
        source_name
    ])
    timestamp_key = "start_time" if source_name == "otel" else "timestamp"
    setattr(records[0], timestamp_key, bundle.window.start + timedelta(seconds=offset))

    assert _provenance_label(run, bundle) == "live"


@pytest.mark.parametrize("source_name", ["otel", "tool_audit"])
@pytest.mark.parametrize("invalid_time", ["missing", "stale", "future", "naive"])
def test_identity_alone_does_not_promote_untimed_or_out_of_window_records(
    source_name: str, invalid_time: str,
) -> None:
    run, bundle = _provenance_case(source_name)
    source = getattr(bundle.sources, source_name)
    records = source.spans if source_name == "otel" else source.records
    invalid_timestamps = {
        "missing": None,
        "stale": bundle.window.start - timedelta(microseconds=1),
        "future": bundle.window.end + timedelta(microseconds=1),
        "naive": bundle.window.start.replace(tzinfo=None),
    }
    setattr(records[0], "start_time" if source_name == "otel" else "timestamp",
            invalid_timestamps[invalid_time])

    assert _provenance_label(run, bundle) == "recorded"


def test_collection_time_caps_an_otherwise_valid_window() -> None:
    run, bundle = _provenance_case()
    bundle.sources.otel.spans[0].start_time = bundle.window.end
    bundle.collected_at = bundle.window.end - timedelta(microseconds=1)

    assert _provenance_label(run, bundle) == "recorded"


@pytest.mark.parametrize("invalid_window", ["missing", "reversed", "naive", "naive_collection"])
def test_unreliable_window_cannot_establish_live_observation(invalid_window: str) -> None:
    run, bundle = _provenance_case()
    if invalid_window == "missing":
        bundle.window = None
    elif invalid_window == "reversed":
        bundle.window.end = bundle.window.start - timedelta(seconds=1)
    elif invalid_window == "naive":
        bundle.window.start = bundle.window.start.replace(tzinfo=None)
    else:
        bundle.collected_at = bundle.collected_at.replace(tzinfo=None)

    assert _provenance_label(run, bundle) == "recorded"


@pytest.mark.parametrize("invalid_identity", ["empty", "foreign", "missing", "foreign_bundle"])
def test_verified_flag_does_not_replace_observation_identity(invalid_identity: str) -> None:
    run, bundle = _provenance_case()
    if invalid_identity == "empty":
        bundle.sources.otel.spans.clear()
    elif invalid_identity == "foreign_bundle":
        bundle.run_id = "RUN-OTHER"
    else:
        bundle.sources.otel.spans[0].run_id = (
            "RUN-OTHER" if invalid_identity == "foreign" else None
        )

    assert _provenance_label(run, bundle) == "recorded"


@pytest.mark.parametrize("source_name", ["otel", "wazuh"])
def test_persisted_canonical_conflict_cannot_be_hidden_by_normalized_run_id(
    source_name: str,
) -> None:
    run, bundle = _provenance_case(source_name)
    source = getattr(bundle.sources, source_name)
    if source_name == "otel":
        source.spans[0].attributes["agentsec.run_id"] = "RUN-OTHER"
    else:
        source.alerts[0].fields["agentsec.run_id"] = "RUN-OTHER"

    assert _provenance_label(run, bundle) == "recorded"


@pytest.mark.parametrize("correlation", ["trusted_fixture", None])
def test_rebased_or_unattested_records_cannot_promote(correlation: str | None) -> None:
    run, bundle = _provenance_case()
    bundle.sources.otel.meta.correlation = correlation

    assert _provenance_label(run, bundle) == "recorded"


def test_a_collector_error_excludes_even_a_persisted_verified_source() -> None:
    from agentsec.models.evidence import CollectorError
    from agentsec.reporting.normalizer import derive_provenance

    run, bundle = _provenance_case()
    bundle.collector_errors.append(CollectorError(source="otel", message="collection failed"))
    provenance = derive_provenance(run, evidence=bundle)

    assert provenance.evidence == "recorded"
    assert provenance.backends == {}


@pytest.mark.parametrize("execution_state", ["absent", "dry_run", "refused", "pending"])
def test_an_unexecuted_run_cannot_be_promoted_by_attached_evidence(execution_state: str) -> None:
    from agentsec.models.run import RunStatus

    run, bundle = _provenance_case()
    if execution_state == "absent":
        run.execution = None
    elif execution_state == "dry_run":
        run.dry_run = True
    else:
        run.status = RunStatus(execution_state)

    assert _provenance_label(run, bundle) == "recorded"


@pytest.mark.parametrize("backend", ["fixture", "cli", None])
def test_stored_transcript_origin_overrides_a_changed_http_target(backend: str | None) -> None:
    from agentsec.models.evidence import SourceMeta, TranscriptSource, TranscriptTurn
    from agentsec.reporting.normalizer import derive_provenance

    run, bundle = _provenance_case()
    bundle.sources.transcript = TranscriptSource(
        turns=[TranscriptTurn(role="assistant", content="Denied")],
        meta=SourceMeta(collector="replay" if backend == "fixture" else "promptfoo",
                        backend=backend),
    )
    current_target = Target(
        id=run.target_id, environment="local",
        adapter=Adapter(kind="http", base_url="http://127.0.0.1:9"),
    )
    provenance = derive_provenance(run, current_target, evidence=bundle)

    assert provenance.evidence == "mixed"
    assert provenance.adapter == (backend or "unknown")
    bundle.sources.otel = None
    assert derive_provenance(run, current_target, evidence=bundle).evidence == "recorded"


def test_unattested_state_diff_retains_a_recorded_component() -> None:
    from agentsec.models.evidence import SourceMeta, StateDiffSource

    run, bundle = _provenance_case()
    bundle.sources.state_diff = StateDiffSource(
        meta=SourceMeta(collector="state_diff", backend="http"),
    )

    assert _provenance_label(run, bundle) == "mixed"
