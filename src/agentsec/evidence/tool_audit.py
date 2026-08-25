"""Tool-call audit collector.

The target is expected to emit one audit record per tool invocation, including
the ones it *denied*. Denials are the interesting half: a scenario passes
prevention because the agent refused, and the audit record is what proves the
refusal came from a policy decision rather than from the model having a good day.

Raw arguments are never ingested — only a digest — so the bundle stays safe to
hand to a read-only gateway.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from agentsec.errors import EvidenceUnavailable
from agentsec.evidence.base import (
    CollectContext,
    canonical_run_id,
    read_json,
    read_jsonl,
    rebase_timestamp,
    require_run_id_value,
    resolve_path,
)
from agentsec.models.evidence import SourceMeta, ToolAuditRecord, ToolAuditSource
from agentsec.policy.allowlist import assert_private_url


def collect_tool_audit(ctx: CollectContext) -> ToolAuditSource:
    backend = ctx.target.evidence.tool_audit
    if backend is None or backend.kind == "none":
        raise EvidenceUnavailable("target has no tool-audit evidence backend")

    if backend.kind == "file":
        path = resolve_path(backend.path, ctx)
        rows = read_jsonl(path) if path.suffix == ".jsonl" else _as_rows(read_json(path))
        records = [
            _normalise(r, ctx=ctx, trusted_fixture=ctx.trusted_fixture) for r in rows
        ]
        if ctx.trusted_fixture:
            origin = min((r.timestamp for r in records if r.timestamp), default=None)
            for record in records:
                record.timestamp = rebase_timestamp(
                    record.timestamp, ctx.window_start, earliest=origin
                )
        return ToolAuditSource(
            records=records,
            meta=SourceMeta(
                collector="tool_audit",
                backend="file",
                query=str(backend.path),
                correlation="trusted_fixture" if ctx.trusted_fixture else "verified",
            ),
        )

    import httpx

    if not backend.url:
        raise EvidenceUnavailable("tool_audit backend kind=http requires a url")

    assert_private_url(backend.url, what="the tool-audit service")
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(
                backend.url.rstrip("/") + "/tool-audit",
                params={
                    "run_id": ctx.run_id,
                    "since": ctx.window_start.isoformat(),
                    "until": ctx.window_end.isoformat(),
                },
            )
            resp.raise_for_status()
            rows = _as_rows(resp.json())
    except httpx.HTTPError as exc:
        raise EvidenceUnavailable(f"tool-audit query failed: {type(exc).__name__}") from exc

    return ToolAuditSource(
        records=[_normalise(r, ctx=ctx) for r in rows],
        meta=SourceMeta(
            collector="tool_audit",
            backend="http",
            query=f"run_id={ctx.run_id}",
            correlation="verified",
        ),
    )


def _as_rows(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        if not all(isinstance(r, dict) for r in raw):
            raise EvidenceUnavailable("tool-audit payload contains a non-object record")
        return raw
    if isinstance(raw, dict):
        for key in ("records", "items", "results"):
            if isinstance(raw.get(key), list):
                if not all(isinstance(r, dict) for r in raw[key]):
                    raise EvidenceUnavailable("tool-audit payload contains a non-object record")
                return raw[key]
    raise EvidenceUnavailable("unrecognised tool-audit payload shape")


def _normalise(
    row: dict[str, Any],
    *,
    ctx: CollectContext | None = None,
    trusted_fixture: bool = False,
) -> ToolAuditRecord:
    decision = str(row.get("decision") or row.get("outcome") or "allow").lower()
    if decision in {"denied", "block", "blocked", "refuse", "refused"}:
        decision = "deny"
    elif decision in {"allowed", "permit", "permitted", "ok"}:
        decision = "allow"
    elif decision in {"escalated", "review", "pending"}:
        decision = "escalate"
    if decision not in {"allow", "deny", "escalate"}:
        raise EvidenceUnavailable(f"unrecognised tool-audit decision: {row.get('decision')!r}")

    timestamp = _maybe_time(row.get("timestamp") or row.get("ts"))
    run_id = canonical_run_id(row)
    if ctx is not None:
        run_id = require_run_id_value(
            run_id,
            ctx.run_id,
            trusted_fixture=trusted_fixture,
            what="tool-audit record",
        )
    return ToolAuditRecord(
        tool=str(row.get("tool") or row.get("tool_name") or ""),
        decision=decision,  # type: ignore[arg-type]
        record_id=row.get("record_id") or row.get("id"),
        principal=row.get("principal") or row.get("user"),
        tenant_id=row.get("tenant_id"),
        arguments_digest=row.get("arguments_digest") or row.get("args_sha256"),
        timestamp=timestamp,
        policy=row.get("policy") or row.get("policy_id"),
        span_id=row.get("span_id"),
        tool_call_id=(
            row.get("tool_call_id")
            or row.get("call_id")
            or row.get("tool.call_id")
            or row.get("agentsec.tool_call_id")
        ),
        run_id=run_id,
    )


def _maybe_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, int | float):
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (OSError, OverflowError, ValueError):
            return None
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None
