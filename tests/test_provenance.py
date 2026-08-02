"""Provenance (#27): a verdict proven against fixtures must not read like a live one.

These are the acceptance-matrix rows from the issue, each pinned down directly
against ``derive_provenance``/``normalize_batch`` rather than requiring a live
target this repository does not ship.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from agentsec.models.run import ExecutionResult, PurpleVerdict, Run, RunStatus, Verdict
from agentsec.models.target import Adapter, Target
from agentsec.reporting.normalizer import (
    Provenance,
    derive_provenance,
    normalize_batch,
    normalize_run,
)
from tests.conftest import REPO_ROOT


def _run(executor: str | None) -> Run:
    now = datetime.now(UTC)
    execution = (
        ExecutionResult(executor=executor, started_at=now, finished_at=now, ok=True)
        if executor
        else None
    )
    verdict = Verdict(
        purple_verdict=PurpleVerdict.SECURE,
        prevention="pass", detection="pass", evidence="pass", response="not_tested",
    )
    return Run(
        run_id="RUN-20260802-001", scenario_id="AGT-XPIA-001", target_id="test-target",
        profile="pr", status=RunStatus.COMPLETED, created_at=now,
        started_at=now, finished_at=now, execution=execution, verdict=verdict,
    )


def _target(adapter_kind: str) -> Target:
    if adapter_kind == "fixture":
        adapter = Adapter(kind="fixture", fixture_dir="fixtures/x")
    else:
        adapter = Adapter(kind="http", base_url="http://127.0.0.1:9")
    return Target(id="test-target", environment="local", adapter=adapter)


def test_replay_against_a_fixture_adapter_is_recorded() -> None:
    prov = derive_provenance(
        _run("replay"), _target("fixture"),
        {"wazuh": "file", "otel": "file", "tool_audit": "file"},
    )
    assert prov == Provenance(
        executor="replay", adapter="fixture", evidence="recorded",
        backends={"wazuh": "file", "otel": "file", "tool_audit": "file"},
    )


def test_live_target_with_live_backends_is_live() -> None:
    prov = derive_provenance(
        _run("promptfoo"), _target("http"),
        {"wazuh": "opensearch", "otel": "http"},
    )
    assert prov.evidence == "live"


def test_live_target_with_a_file_backed_collector_is_mixed_and_named() -> None:
    """The interesting value, and it must not be hidden."""
    prov = derive_provenance(_run("promptfoo"), _target("http"), {"wazuh": "file"})
    assert prov.evidence == "mixed"
    assert prov.backends == {"wazuh": "file"}


def test_a_collector_that_errored_and_contributed_nothing_is_excluded() -> None:
    """Absence from ``evidence_backends`` is how a collector error is represented
    here — it must not be silently folded into ``live`` just because the
    adapter is live."""
    prov = derive_provenance(_run("promptfoo"), _target("http"), {})
    assert prov.backends == {}
    assert prov.evidence == "live"  # the adapter alone; nothing else contributed


def test_unresolvable_target_falls_back_to_the_conservative_label() -> None:
    prov = derive_provenance(_run("replay"), None, {})
    assert prov.adapter == "unknown"
    assert prov.evidence == "recorded"


def test_purple_verdict_is_unchanged_by_provenance() -> None:
    """The one property that must never move: see ADR 0002."""
    run = _run("replay")
    fixture_summary = normalize_run(run, target=_target("fixture"))
    live_summary = normalize_run(
        run, target=_target("http"), evidence_backends={"wazuh": "opensearch"}
    )
    assert fixture_summary.verdict == live_summary.verdict == "secure"
    assert fixture_summary.prevention == live_summary.prevention == "pass"
    assert fixture_summary.provenance.evidence != live_summary.provenance.evidence


def test_batch_rollup_counts_provenance_and_trips_the_banner() -> None:
    fixture_run = normalize_run(_run("replay"), target=_target("fixture"))
    live_run = normalize_run(
        _run("promptfoo"), target=_target("http"), evidence_backends={"wazuh": "opensearch"}
    )

    all_fixture = normalize_batch([fixture_run, fixture_run], profile="pr", target_id="t")
    assert all_fixture["provenance_counts"] == {"recorded": 2, "live": 0, "mixed": 0}
    assert all_fixture["fixture_derived"] is True

    mixed_batch = normalize_batch([fixture_run, live_run], profile="pr", target_id="t")
    assert mixed_batch["provenance_counts"] == {"recorded": 1, "live": 1, "mixed": 0}
    assert mixed_batch["fixture_derived"] is False

    empty_batch = normalize_batch([], profile="pr", target_id="t")
    assert empty_batch["fixture_derived"] is False


def test_bundled_corpus_end_to_end_is_recorded_and_trips_the_banner(service) -> None:  # noqa: ANN001
    """Acceptance-matrix row: bundled corpus, nightly profile."""
    result = service.start_run(target_id="demo-agent-fixture", profile="nightly")
    for s in result.summaries:
        assert s.provenance.executor == "replay"
        assert s.provenance.adapter == "fixture"
        assert s.provenance.evidence == "recorded"
    assert result.report["fixture_derived"] is True
    assert result.report["provenance_counts"] == {"recorded": 4, "live": 0, "mixed": 0}
    # purple_verdict must be exactly the pre-existing expected matrix, unmoved.
    assert result.report["blocking_count"] == 2


def test_a_report_shaped_like_schema_1_x_still_validates() -> None:
    """Existing consumers pinned to 1.x must still validate: provenance is additive."""
    from jsonschema import Draft202012Validator

    schema_path = REPO_ROOT / "schemas" / "dashboard.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    legacy_report = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "profile": "pr",
        "target_id": "demo-agent-fixture",
        "total_runs": 1,
        "verdict_counts": {"secure": 1},
        "axis_counts": {
            axis: {"pass": 1, "fail": 0, "not_tested": 0, "error": 0}
            for axis in ("prevention", "detection", "evidence", "response")
        },
        "secure": 1,
        "blocking_count": 0,
        "blocking_scenarios": [],
        "exit_code": 0,
        "runs": [
            {
                "run_id": "RUN-20260101-001",
                "scenario_id": "AGT-XPIA-001",
                "target_id": "demo-agent-fixture",
                "profile": "pr",
                "status": "completed",
                "purple_verdict": "secure",
                "prevention": "pass",
                "detection": "pass",
                "evidence": "pass",
                "response": "not_tested",
                "blocking": False,
                "gate": "warning",
            }
        ],
    }
    errors = list(Draft202012Validator(schema).iter_errors(legacy_report))
    assert not errors, [str(e) for e in errors]
