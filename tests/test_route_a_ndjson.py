"""Route A accepts correlated AgentShield NDJSON without relaxing evidence truth."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentsec.errors import EvidenceUnavailable
from agentsec.evidence.base import CollectContext
from agentsec.evidence.tool_audit import collect_tool_audit
from agentsec.models.target import Adapter, EvidenceBackends, Target, ToolAuditBackend

RUN_ID = "RUN-route-a-ndjson"
WINDOW_START = datetime(2026, 9, 5, 10, 0, tzinfo=UTC)


def _context(tmp_path: Path, suffix: str) -> CollectContext:
    return CollectContext(
        run_id=RUN_ID,
        scenario_id="AGT-CONFIG-001",
        target=Target(
            id="route-a-staging",
            environment="staging",
            adapter=Adapter(kind="http", base_url="http://127.0.0.1:8787"),
            evidence=EvidenceBackends(
                tool_audit=ToolAuditBackend(kind="file", path=f"runtime{suffix}"),
            ),
        ),
        workspace=tmp_path,
        window_start=WINDOW_START,
        window_end=WINDOW_START + timedelta(seconds=30),
        trusted_fixture=False,
    )


def _rows() -> list[dict[str, object]]:
    return [
        {
            "agentsec.run_id": RUN_ID,
            "timestamp": "2026-09-05T10:00:03Z",
            "tool": "Bash",
            "decision": "block",
            "reason": "reviewed staging policy",
            "durationMs": 1,
            "record_id": "audit-1",
            "tool_call_id": "call-1",
        },
        {
            "agentsec": {"run_id": RUN_ID},
            "timestamp": "2026-09-05T10:00:05Z",
            "tool": "Read",
            "decision": "allow",
            "durationMs": 1,
            "record_id": "audit-2",
            "tool_call_id": "call-2",
        },
    ]


def _write(tmp_path: Path, suffix: str, rows: list[dict[str, object]]) -> None:
    (tmp_path / f"runtime{suffix}").write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )


def test_ndjson_matches_jsonl_without_rebasing_live_records(tmp_path: Path) -> None:
    sources = []
    for suffix in (".ndjson", ".jsonl"):
        _write(tmp_path, suffix, _rows())
        sources.append(collect_tool_audit(_context(tmp_path, suffix)))

    assert sources[0].records == sources[1].records
    for source in sources:
        assert source.meta.correlation == "verified"
        assert [record.run_id for record in source.records] == [RUN_ID, RUN_ID]
        assert [record.decision for record in source.records] == ["deny", "allow"]
        assert [record.tool_call_id for record in source.records] == ["call-1", "call-2"]
        assert [record.timestamp for record in source.records] == [
            WINDOW_START + timedelta(seconds=3),
            WINDOW_START + timedelta(seconds=5),
        ]


@pytest.mark.parametrize("suffix", [".ndjson", ".jsonl"])
def test_malformed_line_fails_closed(tmp_path: Path, suffix: str) -> None:
    _write(tmp_path, suffix, _rows())
    with (tmp_path / f"runtime{suffix}").open("a", encoding="utf-8") as stream:
        stream.write('{"decision":\n')

    with pytest.raises(EvidenceUnavailable, match="malformed JSONL"):
        collect_tool_audit(_context(tmp_path, suffix))


@pytest.mark.parametrize("suffix", [".ndjson", ".jsonl"])
@pytest.mark.parametrize(
    ("correlation", "message"),
    [
        ({}, "missing canonical agentsec.run_id"),
        ({"run_id": RUN_ID}, "missing canonical agentsec.run_id"),
        ({"agentsec.run_id": "RUN-foreign"}, "correlated to another run"),
        (
            {"agentsec.run_id": RUN_ID, "agentsec": {"run_id": "RUN-foreign"}},
            "conflicting canonical agentsec.run_id",
        ),
    ],
    ids=["missing", "generic-alias", "foreign", "conflicting"],
)
def test_invalid_run_correlation_rejects_entire_stream(
    tmp_path: Path, suffix: str, correlation: dict[str, object], message: str
) -> None:
    rows = _rows()
    rows[1].pop("agentsec")
    rows[1].update(correlation)
    _write(tmp_path, suffix, rows)

    with pytest.raises(EvidenceUnavailable, match=message):
        collect_tool_audit(_context(tmp_path, suffix))
