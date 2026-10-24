"""Issue #42: single-run MCP publication carries derived evidence provenance."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator

from agentsec.models.evidence import CollectorError, SourceMeta, StateDiffSource
from agentsec.models.target import Adapter, Target
from agentsec.reporting.publish import (
    PUBLISH_SCHEMA_VERSION,
    PublicationInvalid,
    PublishedRun,
    publish,
)
from tests.conftest import REPO_ROOT
from tests.test_issue77_provenance import _provenance_case


def _store_case(service, case: str):  # noqa: ANN001, ANN202
    run, evidence = _provenance_case()
    if case == "recorded":
        evidence.sources.otel.meta.correlation = "trusted_fixture"
    elif case == "mixed":
        evidence.sources.state_diff = StateDiffSource(
            meta=SourceMeta(collector="state_diff", backend="http")
        )
    elif case == "collector_error":
        evidence.collector_errors.append(
            CollectorError(source="otel", message="collection failed")
        )
    elif case == "no_execution":
        run.execution = None
    elif case in {"live", "missing_target"}:
        pass
    else:  # pragma: no cover - test helper guard
        raise AssertionError(case)
    run.evidence_ref = service._persist_evidence(evidence)
    service.store.save_run(run)
    return run


@pytest.mark.parametrize(
    ("case", "expected_evidence", "expected_adapter"),
    [
        ("recorded", "recorded", "http"),
        ("live", "live", "http"),
        ("mixed", "mixed", "http"),
        ("missing_target", "live", "unknown"),
        ("collector_error", "recorded", "http"),
        ("no_execution", "recorded", "http"),
    ],
)
def test_service_published_run_matches_report_and_dashboard(
    service, monkeypatch, case: str, expected_evidence: str, expected_adapter: str,
) -> None:  # noqa: ANN001
    """Every surface delegates to the same ADR 0010 derivation."""
    run = _store_case(service, case)
    if case != "missing_target":
        target = Target(
            id=run.target_id,
            environment="local",
            adapter=Adapter(kind="http", base_url="http://127.0.0.1:9"),
        )
        monkeypatch.setattr(service, "get_target", lambda _: target)

    body = publish("run", service.get_published_run(run.run_id))
    report, _, _ = service._rollup(target_id=run.target_id, profile=run.profile, limit=10)
    dashboard = service.dashboard(target_id=run.target_id, profile=run.profile, limit=10)

    provenance = body["run"]["provenance"]
    assert provenance == report["runs"][0]["provenance"]
    assert provenance == dashboard["purple"]["runs"][0]["provenance"]
    assert provenance["evidence"] == expected_evidence
    assert provenance["adapter"] == expected_adapter
    assert body["run"]["verdict"]["purple_verdict"] == "secure"


def test_missing_evidence_uses_the_conservative_shared_fallback(service) -> None:  # noqa: ANN001
    run, _ = _provenance_case()
    service.store.save_run(run)

    body = publish("run", service.get_published_run(run.run_id))

    assert body["run"]["provenance"] == {
        "executor": "replay",
        "adapter": "unknown",
        "evidence": "recorded",
        "backends": {},
    }


def test_published_run_validates_against_its_explicit_schema(service) -> None:  # noqa: ANN001
    run = _store_case(service, "live")
    body = publish("run", service.get_published_run(run.run_id))
    schema = json.loads(
        (REPO_ROOT / "schemas" / "published-run.schema.json").read_text(encoding="utf-8")
    )

    assert body["schema_version"] == PUBLISH_SCHEMA_VERSION == "1.6.0"
    assert not list(Draft202012Validator(schema).iter_errors(body))


def test_malformed_service_context_fails_closed(service) -> None:  # noqa: ANN001
    run, _ = _provenance_case()
    malformed = PublishedRun(run=run, provenance={"backends": "file"})

    with pytest.raises(PublicationInvalid) as exc:
        publish("run", malformed)
    assert exc.value.details == {"schema": "published-run.schema.json"}


def test_published_provenance_adds_no_observed_identifiers(service) -> None:  # noqa: ANN001
    run = _store_case(service, "live")
    body = publish("run", service.get_published_run(run.run_id))
    published = json.dumps(body)

    assert "evidence_ref" not in body["run"]
    assert "raw_ref" not in (body["run"]["execution"] or {})
    assert "approval_id" not in body["run"]
    assert str(service.settings.workspace) not in published
    assert "principal" not in published
    assert "tenant" not in published
