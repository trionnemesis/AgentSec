"""Tool-call audit collector.

The target is expected to emit one audit record per tool invocation, including
the ones it *denied*. Denials are the interesting half: a scenario passes
prevention because the agent refused, and the audit record is what proves the
refusal came from a policy decision rather than from the model having a good day.

Raw arguments are never ingested — only a digest — so the bundle stays safe to
hand to a read-only gateway.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from agentsec.errors import EvidenceUnavailable
from agentsec.evidence.base import CollectContext, read_json, read_jsonl, resolve_path
from agentsec.models.evidence import SourceMeta, ToolAuditRecord, ToolAuditSource


def collect_tool_audit(ctx: CollectContext) -> ToolAuditSource:
    backend = ctx.target.evidence.tool_audit
    if backend is None or backend.kind == "none":
        raise EvidenceUnavailable("target has no tool-audit evidence backend")

    if backend.kind == "file":
        path = resolve_path(backend.path, ctx)
        rows = read_jsonl(path) if path.suffix == ".jsonl" else _as_rows(read_json(path))
        return ToolAuditSource(
            records=[_normalise(r) for r in rows],
            meta=SourceMeta(collector="tool_audit", backend="file", query=str(backend.path)),
        )

    import httpx

    if not backend.url:
        raise EvidenceUnavailable("tool_audit backend kind=http requires a url")
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
        records=[_normalise(r) for r in rows],
        meta=SourceMeta(collector="tool_audit", backend="http", query=f"run_id={ctx.run_id}"),
    )


def _as_rows(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    if isinstance(raw, dict):
        for key in ("records", "items", "results"):
            if isinstance(raw.get(key), list):
                return [r for r in raw[key] if isinstance(r, dict)]
    raise EvidenceUnavailable("unrecognised tool-audit payload shape")


def _normalise(row: dict[str, Any]) -> ToolAuditRecord:
    decision = str(row.get("decision") or row.get("outcome") or "allow").lower()
    if decision in {"denied", "block", "blocked", "refuse", "refused"}:
        decision = "deny"
    elif decision in {"allowed", "permit", "permitted", "ok"}:
        decision = "allow"
    elif decision in {"escalated", "review", "pending"}:
        decision = "escalate"
    if decision not in {"allow", "deny", "escalate"}:
        raise EvidenceUnavailable(f"unrecognised tool-audit decision: {row.get('decision')!r}")

    return ToolAuditRecord(
        tool=str(row.get("tool") or row.get("tool_name") or ""),
        decision=decision,  # type: ignore[arg-type]
        record_id=row.get("record_id") or row.get("id"),
        principal=row.get("principal") or row.get("user"),
        tenant_id=row.get("tenant_id"),
        arguments_digest=row.get("arguments_digest") or row.get("args_sha256"),
        timestamp=_maybe_time(row.get("timestamp") or row.get("ts")),
        policy=row.get("policy") or row.get("policy_id"),
        span_id=row.get("span_id"),
    )


def _maybe_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None
