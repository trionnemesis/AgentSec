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
from agentsec.evidence.base import (
    CollectContext,
    canonical_run_id,
    read_json,
    rebase_timestamp,
    require_run_id_value,
    resolve_path,
)
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
        spans = _parse_otlp(
            raw,
            run_id=ctx.run_id,
            trusted_fixture=ctx.trusted_fixture,
            window_start=ctx.window_start if ctx.trusted_fixture else None,
        )
        return OtelSource(
            spans=spans,
            trace_ids=sorted({s.trace_id for s in spans if s.trace_id}),
            meta=SourceMeta(
                collector="otel",
                backend="file",
                query=str(backend.path),
                correlation="trusted_fixture" if ctx.trusted_fixture else "verified",
            ),
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

    spans = _parse_otlp(body, run_id=ctx.run_id, trusted_fixture=False)
    return OtelSource(
        spans=spans,
        trace_ids=sorted({s.trace_id for s in spans if s.trace_id}),
        meta=SourceMeta(
            collector="otel",
            backend="http",
            query=params["tags"],
            correlation="verified",
        ),
    )


def _parse_otlp(
    raw: Any,
    *,
    run_id: str | None = None,
    trusted_fixture: bool = False,
    window_start: datetime | None = None,
) -> list[OtelSpan]:
    """Accept both OTLP-JSON and a plain list of span dicts.

    Being liberal here is worth it: every tracing backend exports a slightly
    different flavour, and forcing users to write a shim before they can run
    their first scenario is how a tool gets abandoned at step two.
    """
    if isinstance(raw, dict) and "resourceSpans" in raw:
        if not isinstance(raw["resourceSpans"], list):
            raise EvidenceUnavailable("OTel resourceSpans is not a list")
        spans = _parse_resource_spans(raw["resourceSpans"])
    elif isinstance(raw, dict) and "spans" in raw:
        if not isinstance(raw["spans"], list) or not all(
            isinstance(s, dict) for s in raw["spans"]
        ):
            raise EvidenceUnavailable("OTel spans is not a list of objects")
        spans = [_parse_simple(s) for s in raw["spans"]]
    elif isinstance(raw, list):
        if not all(isinstance(s, dict) for s in raw):
            raise EvidenceUnavailable("OTel payload is not a list of objects")
        spans = [_parse_simple(s) for s in raw]
    else:
        raise EvidenceUnavailable("unrecognised OTel payload shape")

    if run_id is not None:
        origin = min(
            (s.start_time for s in spans if s.start_time is not None),
            default=None,
        )
        for span in spans:
            span.run_id = require_run_id_value(
                span.run_id or canonical_run_id(span.attributes),
                run_id,
                trusted_fixture=trusted_fixture,
                what="OTel span",
            )
            # A recorded fixture is explicitly normalised to the current run
            # window; live event timestamps are never rewritten.
            if trusted_fixture and window_start is not None:
                span.start_time = rebase_timestamp(
                    span.start_time, window_start, earliest=origin
                )
                span.end_time = rebase_timestamp(
                    span.end_time, window_start, earliest=origin
                )
    return spans


def _parse_resource_spans(resource_spans: list[dict[str, Any]]) -> list[OtelSpan]:
    out: list[OtelSpan] = []
    for rs in resource_spans:
        resource_attrs = _kv_list(rs.get("resource", {}).get("attributes", []))
        for scope in rs.get("scopeSpans", []) or rs.get("instrumentationLibrarySpans", []):
            for span in scope.get("spans", []):
                span_attrs = _kv_list(span.get("attributes", []))
                attrs = {**resource_attrs, **span_attrs}
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
                        run_id=_span_run_id(
                            span_attrs, span, resource_attrs=resource_attrs
                        ),
                        tool_call_id=_tool_call_id(attrs, span),
                    )
                )
    return out


def _parse_simple(span: dict[str, Any]) -> OtelSpan:
    attrs = span.get("attributes", {})
    attrs = _parse_attributes(attrs)
    return OtelSpan(
        name=span.get("name", ""),
        trace_id=span.get("trace_id") or span.get("traceId"),
        span_id=span.get("span_id") or span.get("spanId"),
        parent_span_id=span.get("parent_span_id") or span.get("parentSpanId") or None,
        start_time=_maybe_time(span.get("start_time") or span.get("startTime")),
        end_time=_maybe_time(span.get("end_time") or span.get("endTime")),
        status=_status_of(span.get("status")),
        attributes=attrs,
        run_id=_span_run_id(attrs, span),
        tool_call_id=_tool_call_id(attrs, span),
    )


def _span_run_id(
    attrs: Any,
    span: dict[str, Any],
    *,
    resource_attrs: Any = None,
) -> str | None:
    """Resolve supported OTel locations without hiding conflicting values."""
    observed = [
        value
        for value in (
            canonical_run_id(resource_attrs),
            canonical_run_id(attrs),
            canonical_run_id(span),
        )
        if value is not None
    ]
    if any(value != observed[0] for value in observed[1:]):
        raise EvidenceUnavailable("OTel span has conflicting canonical agentsec.run_id values")
    return observed[0] if observed else None


def _tool_call_id(attrs: Any, span: dict[str, Any]) -> str | None:
    if isinstance(attrs, dict):
        for key in (
            "agentsec.tool_call_id",
            "tool_call_id",
            "tool.call_id",
            "gen_ai.tool.call.id",
        ):
            value = attrs.get(key)
            if value not in (None, ""):
                return str(value)
    for key in ("tool_call_id", "toolCallId", "call_id"):
        value = span.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def _decode_kv_value(raw: Any) -> Any:
    if not isinstance(raw, dict):
        return raw

    for key in ("stringValue", "intValue", "doubleValue", "boolValue"):
        if key in raw:
            value = raw[key]
            return int(value) if key == "intValue" and isinstance(value, str) else value
    return str(raw)


def _decode_kv_value_scalar(raw: Any) -> Any:
    value = _decode_kv_value(raw)
    if isinstance(value, dict | list):
        return str(value)
    return value


def _decode_kv_nested_run_id_values(raw: Any) -> list[str]:
    if not isinstance(raw, dict):
        return []

    nested_values: list[str] = []
    for kv_key in ("kvlistValue", "kvListValue"):
        nested_value_container = raw.get(kv_key)
        if isinstance(nested_value_container, dict):
            raw_values = nested_value_container.get("values")
            if isinstance(raw_values, list):
                for nested in raw_values:
                    if not isinstance(nested, dict):
                        continue
                    if nested.get("key") != "run_id":
                        continue
                    value = nested.get("value")
                    if not isinstance(value, dict):
                        continue
                    parsed = _decode_kv_value_scalar(value)
                    if parsed is None or parsed == "":
                        continue
                    nested_values.append(str(parsed))

    struct_value = raw.get("structValue")
    if isinstance(struct_value, dict):
        fields = struct_value.get("fields")
        if isinstance(fields, dict):
            value = fields.get("run_id")
            if isinstance(value, dict) and "value" in value:
                parsed = _decode_kv_value_scalar(value.get("value"))
                if parsed is not None and parsed != "":
                    nested_values.append(str(parsed))
    return nested_values


def _canonical_nested_run_id(raw: Any) -> str | None:
    values = _decode_kv_nested_run_id_values(raw)
    if not values:
        return None
    first = values[0]
    if any(value != first for value in values[1:]):
        raise EvidenceUnavailable(
            "OTel attributes have conflicting canonical agentsec.run_id values"
        )
    return first


def _canonical_kv_alias_run_id(key: str, value: Any) -> str | None:
    if key == "agentsec.run_id":
        return None if value is None else str(value)
    if key == "agentsec":
        return _canonical_nested_run_id(value)
    return None


def _normalise_agentsec_alias(
    key: str, raw_value: Any, observed_run_id: str | None
) -> tuple[str, Any, str | None]:
    parsed = _decode_kv_value_scalar(raw_value)
    alias_key = key
    if key == "agentsec":
        nested_run_id = _canonical_nested_run_id(raw_value)
        if nested_run_id is not None:
            parsed = nested_run_id
            alias_key = "agentsec.run_id"
            alias_run_id = nested_run_id
        else:
            if isinstance(raw_value, dict):
                direct_run_id = raw_value.get("run_id")
                if direct_run_id not in (None, ""):
                    parsed = str(direct_run_id)
                    alias_key = "agentsec.run_id"
                    alias_run_id = parsed
                else:
                    parsed = _decode_kv_value_scalar(raw_value)
                    alias_key = key
                    alias_run_id = None
            else:
                alias_key = key
                alias_run_id = None
    else:
        alias_run_id = _canonical_kv_alias_run_id(key, parsed)

    if alias_run_id is not None and observed_run_id is not None:
        if observed_run_id != alias_run_id:
            raise EvidenceUnavailable(
                "OTel attributes have conflicting canonical agentsec.run_id values"
            )
        return alias_key, parsed, observed_run_id
    if alias_run_id is not None:
        return alias_key, parsed, alias_run_id
    return alias_key, parsed, observed_run_id


def _parse_attributes(attrs: Any) -> dict[str, Any]:
    if isinstance(attrs, list):
        return _kv_list(attrs)
    if isinstance(attrs, dict):
        return _kv_map(attrs)
    return {}


def _kv_map(attrs: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    observed_run_id: str | None = None
    for key, raw_value in attrs.items():
        if not isinstance(key, str):
            continue
        alias_key, parsed, next_observed_run_id = _normalise_agentsec_alias(
            key, raw_value, observed_run_id
        )
        if (
            alias_key == "agentsec.run_id"
            and alias_key in out
            and str(out[alias_key]) != str(parsed)
        ):
            raise EvidenceUnavailable(
                "OTel attributes have conflicting canonical agentsec.run_id values"
            )
        out[alias_key] = parsed
        observed_run_id = next_observed_run_id
    return out


def _kv_list(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Unwrap OTLP's ``[{key, value:{stringValue: ...}}]`` attribute encoding."""
    out: dict[str, Any] = {}
    observed_run_id: str | None = None
    for item in items:
        key = item.get("key")
        if key is None:
            continue
        if not isinstance(key, str):
            continue

        raw_value = item.get("value")
        alias_key, parsed, observed_run_id = _normalise_agentsec_alias(
            key, raw_value, observed_run_id
        )

        if (
            alias_key == "agentsec.run_id"
            and alias_key in out
            and str(out[alias_key]) != str(parsed)
        ):
            raise EvidenceUnavailable(
                "OTel attributes have conflicting canonical agentsec.run_id values"
            )
        out[alias_key] = parsed
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
