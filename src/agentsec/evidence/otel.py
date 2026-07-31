"""OpenTelemetry span collector.

``file`` reads an OTLP-JSON dump (the file exporter's output, or a Jaeger/Tempo
export). ``http`` queries a Tempo-compatible search API. Both flatten into
``OtelSpan``.

Span attributes are the load-bearing part: an assertion like
``agentsec.policy.decision = deny`` is how the evidence axis proves the agent's
policy engine actually ran, rather than the agent merely happening to refuse.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from agentsec.errors import EvidenceUnavailable
from agentsec.evidence.base import CollectContext, read_json, resolve_path
from agentsec.models.evidence import OtelSource, OtelSpan, SourceMeta
from agentsec.policy.allowlist import assert_private_url

SpanStatus = Literal["unset", "ok", "error"]

_STATUS: dict[object, SpanStatus] = {
    0: "unset", 1: "ok", 2: "error",
    "STATUS_CODE_UNSET": "unset", "STATUS_CODE_OK": "ok", "STATUS_CODE_ERROR": "error",
    "unset": "unset", "ok": "ok", "error": "error",
}


def _status_of(raw: Any) -> SpanStatus:
    """Normalise any backend's status encoding. Unknown values are not errors."""
    if isinstance(raw, dict):
        raw = raw.get("code")
    return _STATUS.get(raw, "unset")


def collect_otel(ctx: CollectContext) -> OtelSource:
    backend = ctx.target.evidence.otel
    if backend is None or backend.kind == "none":
        raise EvidenceUnavailable("target has no OTel evidence backend")

    if backend.kind == "file":
        raw = read_json(resolve_path(backend.path, ctx))
        spans = _parse_otlp(raw)
        return OtelSource(
            spans=spans,
            trace_ids=sorted({s.trace_id for s in spans if s.trace_id}),
            meta=SourceMeta(collector="otel", backend="file", query=str(backend.path)),
        )

    return _collect_http(ctx)


def _collect_http(ctx: CollectContext) -> OtelSource:
    import httpx

    backend = ctx.target.evidence.otel
    assert backend is not None
    if not backend.url:
        raise EvidenceUnavailable("otel backend kind=http requires a url")

    assert_private_url(backend.url, what="the OTel trace store")

    params: dict[str, Any] = {
        "start": int(ctx.window_start.timestamp()),
        "end": int(ctx.window_end.timestamp()),
        "limit": 500,
    }
    tags = [f"agentsec.run_id={ctx.run_id}"]
    if backend.service_name:
        tags.append(f"service.name={backend.service_name}")
    params["tags"] = " ".join(tags)

    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(backend.url.rstrip("/") + "/api/search", params=params)
            resp.raise_for_status()
            body = resp.json()
    except httpx.HTTPError as exc:
        raise EvidenceUnavailable(f"OTel backend query failed: {type(exc).__name__}") from exc

    spans = _parse_otlp(body)
    return OtelSource(
        spans=spans,
        trace_ids=sorted({s.trace_id for s in spans if s.trace_id}),
        meta=SourceMeta(collector="otel", backend="http", query=params["tags"]),
    )


def _parse_otlp(raw: Any) -> list[OtelSpan]:
    """Accept both OTLP-JSON and a plain list of span dicts.

    Being liberal here is worth it: every tracing backend exports a slightly
    different flavour, and forcing users to write a shim before they can run
    their first scenario is how a tool gets abandoned at step two.
    """
    if isinstance(raw, dict) and "resourceSpans" in raw:
        return _parse_resource_spans(raw["resourceSpans"])
    if isinstance(raw, dict) and "spans" in raw:
        return [_parse_simple(s) for s in raw["spans"]]
    if isinstance(raw, list):
        return [_parse_simple(s) for s in raw if isinstance(s, dict)]
    raise EvidenceUnavailable("unrecognised OTel payload shape")


def _parse_resource_spans(resource_spans: list[dict[str, Any]]) -> list[OtelSpan]:
    out: list[OtelSpan] = []
    for rs in resource_spans:
        resource_attrs = _kv_list(rs.get("resource", {}).get("attributes", []))
        for scope in rs.get("scopeSpans", []) or rs.get("instrumentationLibrarySpans", []):
            for span in scope.get("spans", []):
                attrs = {**resource_attrs, **_kv_list(span.get("attributes", []))}
                out.append(
                    OtelSpan(
                        name=span.get("name", ""),
                        trace_id=span.get("traceId"),
                        span_id=span.get("spanId"),
                        parent_span_id=span.get("parentSpanId") or None,
                        start_time=_nanos(span.get("startTimeUnixNano")),
                        end_time=_nanos(span.get("endTimeUnixNano")),
                        status=_status_of(span.get("status")),
                        attributes=attrs,
                    )
                )
    return out


def _parse_simple(span: dict[str, Any]) -> OtelSpan:
    attrs = span.get("attributes", {})
    if isinstance(attrs, list):
        attrs = _kv_list(attrs)
    return OtelSpan(
        name=span.get("name", ""),
        trace_id=span.get("trace_id") or span.get("traceId"),
        span_id=span.get("span_id") or span.get("spanId"),
        parent_span_id=span.get("parent_span_id") or span.get("parentSpanId") or None,
        start_time=_maybe_time(span.get("start_time") or span.get("startTime")),
        end_time=_maybe_time(span.get("end_time") or span.get("endTime")),
        status=_status_of(span.get("status")),
        attributes={k: v for k, v in attrs.items()} if isinstance(attrs, dict) else {},
    )


def _kv_list(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Unwrap OTLP's ``[{key, value:{stringValue: ...}}]`` attribute encoding."""
    out: dict[str, Any] = {}
    for item in items:
        key = item.get("key")
        if key is None:
            continue
        value = item.get("value")
        if isinstance(value, dict):
            for vk in ("stringValue", "intValue", "doubleValue", "boolValue"):
                if vk in value:
                    v = value[vk]
                    out[key] = int(v) if vk == "intValue" and isinstance(v, str) else v
                    break
            else:
                out[key] = str(value)
        else:
            out[key] = value
    return out


def _nanos(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        return datetime.fromtimestamp(int(value) / 1e9, tz=UTC)
    except (TypeError, ValueError, OSError):
        return None


def _maybe_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, int | float):
        return datetime.fromtimestamp(float(value), tz=UTC)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None
