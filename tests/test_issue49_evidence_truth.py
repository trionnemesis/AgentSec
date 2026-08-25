"""Regression coverage for Issue #49's evidence truthfulness boundaries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from agentsec.errors import EvidenceUnavailable
from agentsec.evaluation.axes import (
    evaluate_detection,
    evaluate_evidence,
    evaluate_prevention,
    evaluate_response,
)
from agentsec.evidence import collector as collector_module
from agentsec.evidence.base import CollectContext, canonical_run_id
from agentsec.evidence.collector import EvidenceCollector
from agentsec.evidence.otel import _parse_otlp
from agentsec.evidence.tool_audit import _normalise as normalise_tool_audit
from agentsec.evidence.tool_audit import collect_tool_audit
from agentsec.evidence.wazuh import _normalise as normalise_wazuh
from agentsec.evidence.wazuh import collect_wazuh
from agentsec.models.evidence import (
    CollectorError,
    Evidence,
    EvidenceSources,
    EvidenceWindow,
    OtelSource,
    OtelSpan,
    SourceMeta,
    ToolAuditRecord,
    ToolAuditSource,
    TranscriptSource,
    WazuhAlert,
    WazuhSource,
)
from agentsec.models.scenario import Scenario
from agentsec.models.target import (
    Adapter,
    EvidenceBackends,
    Target,
    ToolAuditBackend,
    WazuhBackend,
)
from agentsec.scenario.loader import load_scenario_file
from tests.conftest import REPO_ROOT

NOW = datetime(2026, 7, 28, 9, 0, tzinfo=UTC)


def _scenario(name: str) -> Scenario:
    return load_scenario_file(REPO_ROOT / "scenarios" / f"{name}.yaml")


def _detection_only() -> Scenario:
    raw = _scenario("AGT-XPIA-001").model_dump(mode="json")
    raw["spec"]["contract"] = {"detection": raw["spec"]["contract"]["detection"]}
    return Scenario.model_validate(raw)


def _evidence(
    *,
    run_id: str = "RUN-20260728-001",
    wazuh: WazuhSource | None = None,
    otel: OtelSource | None = None,
    audit: ToolAuditSource | None = None,
) -> Evidence:
    return Evidence(
        run_id=run_id,
        collected_at=NOW,
        window=EvidenceWindow(start=NOW, end=NOW + timedelta(seconds=300)),
        sources=EvidenceSources(
            transcript=TranscriptSource(), wazuh=wazuh, otel=otel, tool_audit=audit
        ),
    )


def _assert_scalar_attributes(attributes: dict[str, Any]) -> None:
    assert all(isinstance(v, (str, int, float, bool)) or v is None for v in attributes.values())


def _alert(timestamp: datetime, *, run_id: str | None = "RUN-20260728-001") -> WazuhAlert:
    return WazuhAlert(rule_id="100501", rule_level=10, timestamp=timestamp, run_id=run_id)


def _target(tmp_path: Path, *, backend: EvidenceBackends, adapter_kind: str = "http") -> Target:
    adapter = (
        Adapter(kind="fixture", fixture_dir="fixtures")
        if adapter_kind == "fixture"
        else Adapter(kind="http", base_url="http://127.0.0.1:8080")
    )
    return Target(
        id="issue49-target",
        environment="local",
        adapter=adapter,
        evidence=backend,
    )


def test_alert_three_seconds_into_120_second_sla_passes() -> None:
    scenario = _scenario("AGT-XPIA-001")
    result = evaluate_detection(
        scenario,
        _evidence(wazuh=WazuhSource(alerts=[_alert(NOW + timedelta(seconds=3))])),
    )
    assert result.status.value == "pass"


def test_alert_after_detection_deadline_fails() -> None:
    scenario = _scenario("AGT-XPIA-001")
    result = evaluate_detection(
        scenario,
        _evidence(wazuh=WazuhSource(alerts=[_alert(NOW + timedelta(seconds=121))])),
    )
    assert result.status.value == "fail"


def test_live_alert_from_another_run_cannot_satisfy_detection() -> None:
    source = WazuhSource(
        alerts=[_alert(NOW + timedelta(seconds=3), run_id="RUN-other")],
        meta=SourceMeta(collector="wazuh", backend="opensearch", correlation="verified"),
    )
    result = evaluate_detection(_scenario("AGT-XPIA-001"), _evidence(wazuh=source))
    assert result.status.value == "error"


def test_missing_run_correlation_without_source_meta_is_error() -> None:
    source = WazuhSource(
        alerts=[_alert(NOW + timedelta(seconds=3), run_id=None)],
    )
    result = evaluate_detection(_scenario("AGT-XPIA-001"), _evidence(wazuh=source))
    assert result.status.value == "error"
    assert "missing current-run canonical correlation" in (result.summary or "")


def test_trusted_file_fixture_is_the_only_missing_run_id_exemption() -> None:
    source = WazuhSource(
        alerts=[_alert(NOW + timedelta(seconds=3), run_id=None)],
        meta=SourceMeta(
            collector="wazuh", backend="file", correlation="trusted_fixture"
        ),
    )
    result = evaluate_detection(_scenario("AGT-XPIA-001"), _evidence(wazuh=source))
    assert result.status.value == "pass"


def test_canonical_run_id_accepts_only_direct_unambiguous_aliases() -> None:
    assert canonical_run_id({"agentsec.run_id": "RUN-1"}) == "RUN-1"
    assert canonical_run_id({"agentsec": {"run_id": "RUN-1"}}) == "RUN-1"
    assert canonical_run_id({"payload": {"agentsec.run_id": "RUN-1"}}) is None
    with pytest.raises(EvidenceUnavailable, match="conflicting canonical"):
        canonical_run_id(
            {"agentsec.run_id": "RUN-1", "agentsec": {"run_id": "RUN-other"}}
        )


def test_nested_argument_run_id_cannot_spoof_tool_audit_correlation(tmp_path: Path) -> None:
    target = _target(tmp_path, backend=EvidenceBackends())
    ctx = CollectContext(
        run_id="RUN-1",
        scenario_id="AGT-XPIA-001",
        target=target,
        workspace=tmp_path,
        window_start=NOW,
        window_end=NOW + timedelta(seconds=120),
    )
    row = {
        "tool": "send_email",
        "decision": "deny",
        "arguments": {"agentsec": {"run_id": "RUN-1"}},
    }
    with pytest.raises(EvidenceUnavailable, match="missing canonical agentsec.run_id"):
        normalise_tool_audit(row, ctx=ctx)


def test_fixture_adapter_does_not_exempt_live_evidence_records(tmp_path: Path) -> None:
    target = _target(tmp_path, backend=EvidenceBackends(), adapter_kind="fixture")
    ctx = CollectContext(
        run_id="RUN-1",
        scenario_id="AGT-XPIA-001",
        target=target,
        workspace=tmp_path,
        window_start=NOW,
        window_end=NOW + timedelta(seconds=120),
        trusted_fixture=True,
    )
    audit_row = {"tool": "send_email", "decision": "deny"}
    wazuh_doc = {"timestamp": NOW.isoformat(), "rule": {"id": "1"}}

    with pytest.raises(EvidenceUnavailable, match="missing canonical"):
        normalise_tool_audit(audit_row, ctx=ctx)
    with pytest.raises(EvidenceUnavailable, match="missing canonical"):
        normalise_wazuh(wazuh_doc, ctx=ctx)

    assert (
        normalise_tool_audit(audit_row, ctx=ctx, trusted_fixture=True).run_id
        == "RUN-1"
    )
    assert normalise_wazuh(wazuh_doc, ctx=ctx, trusted_fixture=True).run_id == "RUN-1"


def test_fixture_file_evidence_still_allows_missing_run_id(tmp_path: Path) -> None:
    fixture = tmp_path / "tool_audit.jsonl"
    fixture.write_text('{"tool":"send_email","decision":"deny"}\n', encoding="utf-8")
    target = _target(
        tmp_path,
        backend=EvidenceBackends(
            tool_audit=ToolAuditBackend(kind="file", path="tool_audit.jsonl")
        ),
        adapter_kind="fixture",
    )
    ctx = CollectContext(
        run_id="RUN-1",
        scenario_id="AGT-XPIA-001",
        target=target,
        workspace=tmp_path,
        window_start=NOW,
        window_end=NOW + timedelta(seconds=120),
        trusted_fixture=True,
    )
    source = collect_tool_audit(ctx)
    assert source.records[0].run_id == "RUN-1"


def test_fixture_adapter_does_not_bypass_live_wazuh_correlation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Response:
        def __init__(self, body: dict[str, Any]) -> None:
            self.body = body

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return self.body

    pages = [
        {
            "_scroll_id": "cursor-1",
            "hits": {
                "hits": [
                    {
                        "_index": "wazuh-alerts-2026.07.28",
                        "_id": "a",
                        "_source": {
                            "timestamp": NOW.isoformat(),
                            "rule": {"id": "1"},
                        },
                    }
                ]
            },
        },
        {"_scroll_id": "cursor-2", "hits": {"hits": []}},
    ]
    requests: list[dict[str, Any]] = []
    cleared: list[dict[str, Any]] = []

    class Client:
        def __init__(self, **_: Any) -> None:
            self.page = 0

        def __enter__(self) -> Client:
            return self

        def __exit__(self, *_: Any) -> None:
            return None

        def post(self, _url: str, *, json: dict[str, Any]) -> Response:
            response = Response(pages[self.page])
            self.page += 1
            requests.append(json.copy())
            return response

        def request(
            self, method: str, _url: str, *, json: dict[str, Any]
        ) -> Response:
            cleared.append(json.copy())
            return Response({})

    monkeypatch.setattr(httpx, "Client", Client)
    target = _target(
        tmp_path,
        backend=EvidenceBackends(
            wazuh=WazuhBackend(kind="opensearch", url="http://127.0.0.1:9200")
        ),
        adapter_kind="fixture",
    )
    ctx = CollectContext(
        run_id="RUN-1",
        scenario_id="AGT-XPIA-001",
        target=target,
        workspace=tmp_path,
        window_start=NOW,
        window_end=NOW + timedelta(seconds=120),
        trusted_fixture=True,
    )
    with pytest.raises(EvidenceUnavailable, match="missing canonical"):
        collect_wazuh(ctx)


def test_fixture_adapter_does_not_bypass_live_tool_audit_correlation(
    tmp_path: Path, monkeypatch
) -> None:
    class Response:
        def __init__(self, payload: Any) -> None:
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> Any:
            return self._payload

    class Client:
        def __init__(self, **_: Any) -> None:
            pass

        def __enter__(self) -> Client:
            return self

        def __exit__(self, *_: Any) -> None:
            return None

        def get(self, *_: Any, **__: Any) -> Response:
            return Response([{"tool": "send_email", "decision": "deny"}])

    monkeypatch.setattr(httpx, "Client", Client)
    target = _target(
        tmp_path,
        backend=EvidenceBackends(
            tool_audit=ToolAuditBackend(
                kind="http",
                url="http://127.0.0.1:8080",
            )
        ),
        adapter_kind="fixture",
    )
    ctx = CollectContext(
        run_id="RUN-1",
        scenario_id="AGT-XPIA-001",
        target=target,
        workspace=tmp_path,
        window_start=NOW,
        window_end=NOW + timedelta(seconds=120),
        trusted_fixture=True,
    )
    with pytest.raises(EvidenceUnavailable, match="missing canonical"):
        collect_tool_audit(ctx)


def test_conflicting_otel_run_id_locations_fail_closed() -> None:
    span = {
        "name": "agent.tool_call",
        "agentsec.run_id": "RUN-other",
        "attributes": {"agentsec.run_id": "RUN-1", "tool.name": "send_email"},
    }
    with pytest.raises(EvidenceUnavailable, match="conflicting canonical"):
        _parse_otlp([span], run_id="RUN-1")


def test_conflicting_otel_resource_and_span_run_ids_fail_closed() -> None:
    payload = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "agentsec.run_id",
                            "value": {"stringValue": "RUN-other"},
                        }
                    ]
                },
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "name": "agent.tool_call",
                                "attributes": [
                                    {
                                        "key": "agentsec.run_id",
                                        "value": {"stringValue": "RUN-1"},
                                    }
                                ],
                            }
                        ]
                    }
                ],
            }
        ]
    }
    with pytest.raises(EvidenceUnavailable, match="conflicting canonical"):
        _parse_otlp(payload, run_id="RUN-1")


def test_duplicate_otel_run_id_attributes_must_agree() -> None:
    span = {
        "name": "agent.tool_call",
        "attributes": [
            {"key": "agentsec.run_id", "value": {"stringValue": "RUN-other"}},
            {"key": "agentsec.run_id", "value": {"stringValue": "RUN-1"}},
        ],
    }
    with pytest.raises(EvidenceUnavailable, match="conflicting canonical"):
        _parse_otlp([span], run_id="RUN-1")


def test_otel_attributes_allow_matching_direct_and_nested_run_id_aliases() -> None:
    payload = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "agentsec.run_id",
                            "value": {"stringValue": "RUN-1"},
                        },
                        {
                            "key": "agentsec",
                            "value": {
                                "kvlistValue": {
                                    "values": [
                                        {
                                            "key": "run_id",
                                            "value": {"stringValue": "RUN-1"},
                                        }
                                    ]
                                }
                            },
                        },
                    ]
                },
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "name": "agent.tool_call",
                                "attributes": [
                                    {
                                        "key": "agentsec.run_id",
                                        "value": {"stringValue": "RUN-1"},
                                    },
                                    {
                                        "key": "agentsec",
                                        "value": {
                                            "kvlistValue": {
                                                "values": [
                                                    {
                                                        "key": "run_id",
                                                        "value": {"stringValue": "RUN-1"},
                                                    }
                                                ]
                                            }
                                        },
                                    },
                                ],
                            }
                        ]
                    }
                ],
            }
        ]
    }
    spans = _parse_otlp(payload, run_id="RUN-1")
    assert spans[0].run_id == "RUN-1"
    assert spans[0].attributes.get("agentsec.run_id") == "RUN-1"
    assert "agentsec" not in spans[0].attributes
    _assert_scalar_attributes(spans[0].attributes)


def test_otel_attributes_allow_nested_resource_run_id_only() -> None:
    payload = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "agentsec",
                            "value": {
                                "kvlistValue": {
                                    "values": [
                                        {
                                            "key": "run_id",
                                            "value": {"stringValue": "RUN-1"},
                                        }
                                    ]
                                }
                            },
                        },
                    ]
                },
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "name": "agent.tool_call",
                                "attributes": [
                                    {
                                        "key": "tool.name",
                                        "value": {"stringValue": "send_email"},
                                    }
                                ],
                            }
                        ]
                    }
                ],
            }
        ]
    }
    spans = _parse_otlp(payload, run_id="RUN-1")
    assert spans[0].run_id == "RUN-1"
    assert spans[0].attributes.get("agentsec.run_id") == "RUN-1"
    _assert_scalar_attributes(spans[0].attributes)


def test_otel_attributes_allow_nested_span_run_id_only() -> None:
    span = {
        "name": "agent.tool_call",
        "attributes": [
            {
                "key": "agentsec",
                "value": {
                    "kvlistValue": {
                        "values": [{"key": "run_id", "value": {"stringValue": "RUN-1"}}]
                    }
                },
            },
            {
                "key": "tool.name",
                "value": {"stringValue": "send_email"},
            },
        ],
    }
    spans = _parse_otlp([span], run_id="RUN-1")
    assert spans[0].run_id == "RUN-1"
    assert spans[0].attributes.get("agentsec.run_id") == "RUN-1"
    _assert_scalar_attributes(spans[0].attributes)


def test_otel_attributes_allow_nested_span_run_id_duplicates_with_same_value() -> None:
    span = {
        "name": "agent.tool_call",
        "attributes": [
            {
                "key": "agentsec",
                "value": {
                    "kvlistValue": {
                        "values": [
                            {"key": "run_id", "value": {"stringValue": "RUN-1"}},
                            {"key": "run_id", "value": {"stringValue": "RUN-1"}},
                        ]
                    }
                },
            },
            {
                "key": "tool.name",
                "value": {"stringValue": "send_email"},
            },
        ],
    }
    spans = _parse_otlp([span], run_id="RUN-1")
    assert spans[0].run_id == "RUN-1"
    assert spans[0].attributes.get("agentsec.run_id") == "RUN-1"
    _assert_scalar_attributes(spans[0].attributes)


def test_otel_attributes_fail_closed_on_nested_span_run_id_duplicates_with_conflict() -> None:
    span = {
        "name": "agent.tool_call",
        "attributes": [
            {
                "key": "agentsec",
                "value": {
                    "kvlistValue": {
                        "values": [
                            {"key": "run_id", "value": {"stringValue": "RUN-other"}},
                            {"key": "run_id", "value": {"stringValue": "RUN-1"}},
                        ]
                    }
                },
            },
            {
                "key": "tool.name",
                "value": {"stringValue": "send_email"},
            },
        ],
    }
    with pytest.raises(EvidenceUnavailable, match="conflicting canonical"):
        _parse_otlp([span], run_id="RUN-1")


def test_otel_attributes_fail_closed_on_direct_and_nested_alias_conflict() -> None:
    payload = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "agentsec.run_id",
                            "value": {"stringValue": "RUN-1"},
                        },
                        {
                            "key": "agentsec",
                            "value": {
                                "kvlistValue": {
                                    "values": [
                                        {
                                            "key": "run_id",
                                            "value": {"stringValue": "RUN-other"},
                                        }
                                    ]
                                }
                            },
                        },
                    ]
                },
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "name": "agent.tool_call",
                                "attributes": [
                                    {"key": "tool.name", "value": {"stringValue": "send_email"}}
                                ],
                            }
                        ]
                    }
                ],
            }
        ]
    }
    with pytest.raises(EvidenceUnavailable, match="conflicting canonical"):
        _parse_otlp(payload, run_id="RUN-1")


def test_resource_direct_and_standard_nested_run_id_foreign_then_expected_fail_closed(
) -> None:
    payload = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "agentsec.run_id",
                            "value": {"stringValue": "RUN-1"},
                        },
                        {
                            "key": "agentsec",
                            "value": {
                                "kvlistValue": {
                                    "values": [
                                        {
                                            "key": "run_id",
                                            "value": {"stringValue": "RUN-other"},
                                        },
                                        {
                                            "key": "run_id",
                                            "value": {"stringValue": "RUN-1"},
                                        },
                                    ]
                                }
                            },
                        },
                    ]
                },
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "name": "agent.tool_call",
                                "attributes": [
                                    {"key": "tool.name", "value": {"stringValue": "send_email"}}
                                ],
                            }
                        ]
                    }
                ],
            }
        ]
    }
    with pytest.raises(EvidenceUnavailable, match="conflicting canonical"):
        _parse_otlp(payload, run_id="RUN-1")


def test_otel_attributes_allow_simple_nested_agentsec_dict() -> None:
    span = {
        "name": "agent.tool_call",
        "attributes": {
            "agentsec": {"run_id": "RUN-1"},
            "tool.name": "send_email",
        },
    }
    spans = _parse_otlp([span], run_id="RUN-1")
    assert spans[0].run_id == "RUN-1"
    assert spans[0].attributes.get("agentsec.run_id") == "RUN-1"
    _assert_scalar_attributes(spans[0].attributes)


def test_prevention_http_egress_rejects_another_runs_otel_span() -> None:
    source = OtelSource(
        spans=[
            OtelSpan(
                name="http.client",
                attributes={"http.url": "https://attacker-collect.example/ingest"},
                run_id="RUN-other",
            )
        ]
    )
    result = evaluate_prevention(_scenario("AGT-CONFIG-001"), _evidence(otel=source))
    assert result.status.value == "error"
    assert "correlated to another run" in (result.summary or "")


def test_prevention_http_egress_rejects_correlation_mismatch_in_otel_attributes() -> None:
    source = OtelSource(
        spans=[
            OtelSpan(
                name="http.client",
                attributes={
                    "http.url": "https://attacker-collect.example/ingest",
                    "agentsec.run_id": "RUN-other",
                },
            )
        ]
    )
    result = evaluate_prevention(_scenario("AGT-CONFIG-001"), _evidence(otel=source))
    assert result.status.value == "error"
    assert "correlated to another run" in (result.summary or "")


def test_two_traced_calls_and_one_audit_record_fail_completeness() -> None:
    scenario = _scenario("AGT-XPIA-001")
    evidence = _evidence(
        otel=OtelSource(
            spans=[
                OtelSpan(
                    name="agent.tool_call",
                    attributes={"tool.name": "send_email"},
                    run_id="RUN-20260728-001",
                ),
                OtelSpan(
                    name="agent.tool_call",
                    attributes={"tool.name": "send_email"},
                    run_id="RUN-20260728-001",
                ),
            ]
        ),
        audit=ToolAuditSource(
            records=[
                ToolAuditRecord(
                    tool="send_email", decision="deny", run_id="RUN-20260728-001"
                )
            ]
        ),
    )
    result = evaluate_evidence(scenario, evidence)
    check = next(c for c in result.checks if c.id == "evidence.tool_audit.complete")
    assert check.status.value == "fail"


def test_response_after_sla_is_response_gap() -> None:
    record = ToolAuditRecord(
        tool="quarantine_session",
        decision="allow",
        timestamp=NOW + timedelta(seconds=61),
        run_id="RUN-20260728-001",
    )
    source = ToolAuditSource(
        records=[record],
        meta=SourceMeta(collector="tool_audit", backend="http", correlation="verified"),
    )
    result = evaluate_response(_scenario("AGT-TENANT-001"), _evidence(audit=source))
    assert result.status.value == "fail"


def test_missing_live_correlation_and_response_timestamp_are_errors() -> None:
    otel = OtelSource(
        spans=[OtelSpan(name="agent.tool_call", attributes={"tool.name": "send_email"})],
        meta=SourceMeta(collector="otel", backend="http", correlation="verified"),
    )
    detection = evaluate_evidence(_scenario("AGT-XPIA-001"), _evidence(otel=otel))
    assert detection.status.value == "error"

    action = ToolAuditSource(
        records=[ToolAuditRecord(tool="quarantine_session", decision="allow")],
        meta=SourceMeta(collector="tool_audit", backend="http", correlation="verified"),
    )
    response = evaluate_response(_scenario("AGT-TENANT-001"), _evidence(audit=action))
    assert response.status.value == "error"


def test_backend_outage_is_collector_error(tmp_path: Path) -> None:
    target = _target(
        tmp_path,
        backend=EvidenceBackends(
            wazuh=WazuhBackend(kind="opensearch", url="http://127.0.0.1:9200")
        ),
    )
    collector = EvidenceCollector(tmp_path, poll_interval_seconds=0)
    result = collector.collect(
        run_id="RUN-20260728-001",
        scenario=_detection_only(),
        target=target,
        transcript=TranscriptSource(),
        window_start=NOW,
        window_end=NOW,
    )
    assert result.collector_errors
    assert isinstance(result.collector_errors[0], CollectorError)


def test_polling_stops_when_alert_arrives_at_three_seconds(monkeypatch, tmp_path: Path) -> None:
    scenario = _detection_only()
    current = [NOW]
    sleeps: list[float] = []

    def clock() -> datetime:
        return current[0]

    def sleeper(seconds: float) -> None:
        sleeps.append(seconds)
        current[0] += timedelta(seconds=seconds)

    def fake_wazuh(ctx: CollectContext) -> WazuhSource:
        alerts = [_alert(current[0])] if current[0] >= NOW + timedelta(seconds=3) else []
        return WazuhSource(alerts=alerts)

    monkeypatch.setattr(collector_module, "collect_wazuh", fake_wazuh)
    target = _target(
        tmp_path,
        backend=EvidenceBackends(wazuh=WazuhBackend(kind="file", path="ignored")),
    )
    result = EvidenceCollector(
        tmp_path, clock=clock, sleeper=sleeper, poll_interval_seconds=1
    ).collect(
        run_id="RUN-20260728-001",
        scenario=scenario,
        target=target,
        transcript=TranscriptSource(),
        window_start=NOW,
    )
    assert result.sources.wazuh is not None
    assert len(result.sources.wazuh.alerts) == 1
    assert sleeps == [1, 1, 1]


def test_wazuh_pagination_consumes_each_page_once(monkeypatch, tmp_path: Path) -> None:
    class Response:
        def __init__(self, body: dict[str, Any]) -> None:
            self.body = body

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return self.body

    pages = [
        {
            "_scroll_id": "cursor-1",
            "hits": {
                "hits": [
                    {
                        "_index": "wazuh-alerts-2026.07.28",
                        "_id": "a",
                        "_source": {
                            "timestamp": NOW.isoformat(),
                            "agentsec.run_id": "RUN-1",
                            "rule": {"id": "1"},
                        },
                    }
                ]
            }
        },
        {
            "_scroll_id": "cursor-2",
            "hits": {
                "hits": [
                    {
                        "_index": "wazuh-alerts-2026.07.28",
                        "_id": "b",
                        "_source": {
                            "timestamp": NOW.isoformat(),
                            "agentsec.run_id": "RUN-1",
                            "rule": {"id": "2"},
                        },
                    }
                ]
            }
        },
        {"_scroll_id": "cursor-3", "hits": {"hits": []}},
    ]
    requests: list[tuple[str, dict[str, Any]]] = []
    cleared: list[tuple[str, dict[str, Any]]] = []

    class Client:
        def __init__(self, **_: Any) -> None:
            pass

        def __enter__(self) -> Client:
            return self

        def __exit__(self, *_: Any) -> None:
            return None

        def post(self, url: str, *, json: dict[str, Any]) -> Response:
            requests.append((url, json.copy()))
            return Response(pages[len(requests) - 1])

        def request(
            self, method: str, url: str, *, json: dict[str, Any]
        ) -> Response:
            assert method == "DELETE"
            cleared.append((url, json.copy()))
            return Response({})

    monkeypatch.setattr(httpx, "Client", Client)
    target = _target(
        tmp_path,
        backend=EvidenceBackends(wazuh=WazuhBackend(kind="opensearch", url="http://127.0.0.1:9200")),
    )
    ctx = CollectContext(
        run_id="RUN-1",
        scenario_id="AGT-XPIA-001",
        target=target,
        workspace=tmp_path,
        window_start=NOW,
        window_end=NOW + timedelta(seconds=120),
    )
    source = collect_wazuh(ctx)
    assert [alert.alert_id for alert in source.alerts] == ["a", "b"]
    assert len(requests) == 3
    assert requests[0][0].endswith("/wazuh-alerts-*/_search?scroll=1m")
    assert requests[0][1]["sort"] == ["_doc"]
    assert "_id" not in str(requests[0][1]["sort"])
    assert requests[1][0].endswith("/_search/scroll")
    assert requests[1][1] == {"scroll": "1m", "scroll_id": "cursor-1"}
    assert requests[2][1] == {"scroll": "1m", "scroll_id": "cursor-2"}
    assert cleared == [
        (
            "http://127.0.0.1:9200/_search/scroll",
            {"scroll_id": "cursor-3"},
        )
    ]


def test_wazuh_duplicate_page_fails_and_clears_latest_scroll(monkeypatch, tmp_path: Path) -> None:
    class Response:
        def __init__(self, body: dict[str, Any]) -> None:
            self.body = body

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return self.body

    hit = {
        "_index": "wazuh-alerts-2026.07.28",
        "_id": "duplicate",
        "_source": {
            "timestamp": NOW.isoformat(),
            "agentsec.run_id": "RUN-1",
            "rule": {"id": "1"},
        },
    }
    pages = [
        {"_scroll_id": "cursor-1", "hits": {"hits": [hit]}},
        {"_scroll_id": "cursor-2", "hits": {"hits": [hit]}},
    ]
    cleared: list[dict[str, Any]] = []

    class Client:
        def __init__(self, **_: Any) -> None:
            self.page = 0

        def __enter__(self) -> Client:
            return self

        def __exit__(self, *_: Any) -> None:
            return None

        def post(self, _url: str, *, json: dict[str, Any]) -> Response:
            response = Response(pages[self.page])
            self.page += 1
            return response

        def request(
            self, method: str, _url: str, *, json: dict[str, Any]
        ) -> Response:
            assert method == "DELETE"
            cleared.append(json.copy())
            return Response({})

    monkeypatch.setattr(httpx, "Client", Client)
    target = _target(
        tmp_path,
        backend=EvidenceBackends(
            wazuh=WazuhBackend(kind="opensearch", url="http://127.0.0.1:9200")
        ),
    )
    ctx = CollectContext(
        run_id="RUN-1",
        scenario_id="AGT-XPIA-001",
        target=target,
        workspace=tmp_path,
        window_start=NOW,
        window_end=NOW + timedelta(seconds=120),
    )
    with pytest.raises(EvidenceUnavailable, match="duplicate hit"):
        collect_wazuh(ctx)
    assert cleared == [{"scroll_id": "cursor-2"}]
