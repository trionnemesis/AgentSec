"""Normalised evidence bundle.

Collectors translate Wazuh/OTel/audit-log/database formats into these shapes.
The evaluator only ever sees this, which is what makes swapping a SIEM a
one-collector job instead of a rewrite.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Scalar = str | int | float | bool | None


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceMeta(_Base):
    collector: str
    backend: str | None = None
    query: str | None = None
    """Redacted description of the query issued. Kept for audit, never credentials."""
    # Live sources must prove that every record belongs to the current run.
    # ``trusted_fixture`` is deliberately explicit: the bundled recordings were
    # captured before run IDs existed and are normalised only at that boundary.
    correlation: Literal["verified", "trusted_fixture"] | None = None


class TranscriptTurn(_Base):
    role: Literal["user", "assistant", "system", "tool"]
    content: str
    step_id: str | None = None
    principal: str | None = None
    timestamp: datetime | None = None


class TranscriptSource(_Base):
    turns: list[TranscriptTurn] = Field(default_factory=list)
    meta: SourceMeta | None = None


class OtelSpan(_Base):
    name: str
    trace_id: str | None = None
    span_id: str | None = None
    parent_span_id: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    status: Literal["unset", "ok", "error"] = "unset"
    attributes: dict[str, Scalar] = Field(default_factory=dict)
    run_id: str | None = None
    tool_call_id: str | None = None


class OtelSource(_Base):
    spans: list[OtelSpan] = Field(default_factory=list)
    trace_ids: list[str] = Field(default_factory=list)
    meta: SourceMeta | None = None


class WazuhAlert(_Base):
    rule_id: str
    timestamp: datetime
    alert_id: str | None = None
    rule_description: str | None = None
    rule_level: int | None = None
    rule_groups: list[str] = Field(default_factory=list)
    agent_name: str | None = None
    fields: dict[str, Scalar] = Field(default_factory=dict)
    """Flattened alert document with dot-notation keys, for match_fields assertions."""
    run_id: str | None = None


class WazuhSource(_Base):
    alerts: list[WazuhAlert] = Field(default_factory=list)
    meta: SourceMeta | None = None


class ToolAuditRecord(_Base):
    tool: str
    decision: Literal["allow", "deny", "escalate"]
    record_id: str | None = None
    principal: str | None = None
    tenant_id: str | None = None
    arguments_digest: str | None = None
    timestamp: datetime | None = None
    policy: str | None = None
    span_id: str | None = None
    tool_call_id: str | None = None
    run_id: str | None = None


class ToolAuditSource(_Base):
    records: list[ToolAuditRecord] = Field(default_factory=list)
    meta: SourceMeta | None = None


class StateChange(_Base):
    collection: str
    operation: Literal["insert", "update", "delete"]
    count: int = 1
    keys: dict[str, Scalar] = Field(default_factory=dict)


class StateDiffSource(_Base):
    changes: list[StateChange] = Field(default_factory=list)
    baseline_taken_at: datetime | None = None
    meta: SourceMeta | None = None


class EvidenceSources(_Base):
    transcript: TranscriptSource | None = None
    otel: OtelSource | None = None
    wazuh: WazuhSource | None = None
    tool_audit: ToolAuditSource | None = None
    state_diff: StateDiffSource | None = None


class CollectorError(_Base):
    source: str
    message: str
    fatal: bool = False


class EvidenceWindow(_Base):
    start: datetime
    end: datetime


class Evidence(_Base):
    run_id: str
    collected_at: datetime
    window: EvidenceWindow | None = None
    sources: EvidenceSources = Field(default_factory=EvidenceSources)
    collector_errors: list[CollectorError] = Field(default_factory=list)

    def error_for(self, source: str) -> CollectorError | None:
        for err in self.collector_errors:
            if err.source == source:
                return err
        return None
