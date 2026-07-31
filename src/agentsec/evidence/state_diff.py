"""Database state-diff collector.

The harness never issues SQL. The target exposes a snapshot endpoint (or writes
a snapshot file) keyed by *logical collection names* it has agreed to expose,
and the collector diffs before against after.

This is the deliberate answer to "why not just give the tool a `query_database`
capability": a constrained, target-declared surface cannot be talked into
reading a table nobody meant to expose.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from agentsec.errors import EvidenceUnavailable
from agentsec.evidence.base import CollectContext, read_json, resolve_path
from agentsec.models.evidence import SourceMeta, StateChange, StateDiffSource
from agentsec.policy.allowlist import assert_private_url


def collect_state_diff(ctx: CollectContext) -> StateDiffSource:
    backend = ctx.target.evidence.state_diff
    if backend is None or backend.kind == "none":
        raise EvidenceUnavailable("target has no state-diff evidence backend")

    if backend.kind == "file":
        raw = read_json(resolve_path(backend.path, ctx))
        return StateDiffSource(
            changes=_parse_changes(raw, backend.collections),
            baseline_taken_at=_maybe_time(
                raw.get("baseline_taken_at") if isinstance(raw, dict) else None
            ),
            meta=SourceMeta(collector="state_diff", backend="file", query=str(backend.path)),
        )

    import httpx

    if not backend.url:
        raise EvidenceUnavailable("state_diff backend kind=http requires a url")

    assert_private_url(backend.url, what="the state-diff service")
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(
                backend.url.rstrip("/") + "/state-diff",
                params={
                    "run_id": ctx.run_id,
                    "collections": ",".join(backend.collections),
                },
            )
            resp.raise_for_status()
            raw = resp.json()
    except httpx.HTTPError as exc:
        raise EvidenceUnavailable(f"state-diff query failed: {type(exc).__name__}") from exc

    return StateDiffSource(
        changes=_parse_changes(raw, backend.collections),
        baseline_taken_at=_maybe_time(raw.get("baseline_taken_at")),
        meta=SourceMeta(collector="state_diff", backend="http", query=f"run_id={ctx.run_id}"),
    )


def _parse_changes(raw: Any, declared: list[str]) -> list[StateChange]:
    rows = raw.get("changes") if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        raise EvidenceUnavailable("unrecognised state-diff payload shape")

    allowed = set(declared)
    changes: list[StateChange] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        collection = str(row.get("collection") or row.get("table") or "")
        if allowed and collection not in allowed:
            # A target reporting a collection it never declared is a
            # misconfiguration worth failing on, not quietly dropping: it means
            # the snapshot scope is wider than the operator signed off.
            raise EvidenceUnavailable(
                f"state-diff reported undeclared collection '{collection}'",
                details={"declared": sorted(allowed)},
            )
        operation = str(row.get("operation") or row.get("op") or "update").lower()
        if operation not in {"insert", "update", "delete"}:
            raise EvidenceUnavailable(f"unrecognised state-diff operation: {operation!r}")
        changes.append(
            StateChange(
                collection=collection,
                operation=operation,  # type: ignore[arg-type]
                count=int(row.get("count", 1)),
                keys={k: v for k, v in (row.get("keys") or {}).items()},
            )
        )
    return changes


def _maybe_time(value: Any) -> datetime | None:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None
