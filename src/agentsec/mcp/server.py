"""AgentSec MCP Gateway.

A thin control plane. Its whole job is: authenticate the caller, validate
arguments against the declared schema, ask the policy guard, delegate to
``HarnessService``, and write an audit record. It runs no attacks, holds no
long-lived jobs, and contains no Promptfoo/Wazuh/database logic — all of that
lives behind the service boundary and is equally reachable from the CLI and CI.

Transport is stdio by default (the local-first deployment). A team deployment
puts an HTTP transport with OAuth in front of the same service; see
docs/deployment.md.
"""

from __future__ import annotations

import inspect
import json
import os
import re
from functools import lru_cache
from typing import Any

from jsonschema import Draft202012Validator

from agentsec.config import load_settings
from agentsec.errors import AgentSecError
from agentsec.mcp.contract import RESOURCES, TOOLS, ToolSpec, tool_by_name
from agentsec.mcp.prompts import PROMPTS
from agentsec.models.run import Run
from agentsec.service.harness import BatchResult, HarnessService

#: Set to "1" to refuse every non-read-only tool. This is the read-only report
#: gateway from deployment option C: a Live Artifact dashboard can be pointed at
#: it safely because execution is not merely discouraged, it is absent.
ENV_READ_ONLY = "AGENTSEC_MCP_READ_ONLY"


_READ_ONLY_RUN_SCHEMA = "agentsec.mcp.read_only.run.v1"
_READ_ONLY_EVIDENCE_SCHEMA = "agentsec.mcp.read_only.evidence.v1"


_READ_ONLY_RESOURCE_HANDLERS = {
    "list_targets",
    "get_target_schema",
    "list_scenarios",
    "get_run",
    "get_run_evidence",
    "list_findings",
    "coverage",
    "audit_tail",
}


def _read_only_mode() -> bool:
    return os.environ.get(ENV_READ_ONLY, "").strip().lower() in {"1", "true", "yes"}


def _read_only_run_output(run: Run) -> dict[str, Any]:
    verdict = run.verdict
    execution = run.execution
    return {
        "schema_version": _READ_ONLY_RUN_SCHEMA,
        "run_id": run.run_id,
        "scenario_id": run.scenario_id,
        "target_id": run.target_id,
        "profile": run.profile,
        "status": str(run.status),
        "created_at": run.created_at.isoformat(),
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "dry_run": run.dry_run,
        "refusal_reason": run.refusal_reason,
        "has_evidence": bool(run.evidence_ref),
        "scenario_digest": run.scenario_digest,
        "initiated_by": run.initiated_by,
        "verdict": (
            {
                "purple_verdict": str(verdict.purple_verdict),
                "prevention": str(verdict.prevention),
                "detection": str(verdict.detection),
                "evidence": str(verdict.evidence),
                "response": str(verdict.response),
                "rationale": verdict.rationale,
            }
            if verdict is not None
            else None
        ),
        "execution": (
            {
                "executor": execution.executor,
                "started_at": execution.started_at.isoformat(),
                "finished_at": execution.finished_at.isoformat() if execution.finished_at else None,
                "ok": execution.ok,
                "steps_completed": execution.steps_completed,
                "error": execution.error,
            }
            if execution is not None
            else None
        ),
    }


def _redact_meta(meta: Any) -> Any:
    if not isinstance(meta, dict):
        return None
    return {
        k: v
        for k, v in meta.items()
        if k not in {"query", "tenant", "tenant_id", "principal", "principal_id"}
    }


def _redact_mapping(values: dict[str, Any], *, drop: set[str] | None = None) -> dict[str, Any]:
    forbidden = drop or set()
    redacted: dict[str, Any] = {}
    for key, value in values.items():
        if key in forbidden:
            continue
        norm = str(key).lower()
        if "token" in norm or "secret" in norm or "password" in norm:
            continue
        if isinstance(value, dict):
            redacted[key] = _redact_mapping(value, drop=drop)
        elif isinstance(value, list):
            redacted[key] = [
                _redact_mapping(v, drop=drop) if isinstance(v, dict) else v
                for v in value
            ]
        else:
            redacted[key] = value
    return redacted


def _read_only_evidence_output(evidence: dict[str, Any]) -> dict[str, Any]:
    sources = evidence.get("sources", {})
    transcript = sources.get("transcript") if isinstance(sources, dict) else None
    otel = sources.get("otel") if isinstance(sources, dict) else None
    wazuh = sources.get("wazuh") if isinstance(sources, dict) else None
    tool_audit = sources.get("tool_audit") if isinstance(sources, dict) else None
    state_diff = sources.get("state_diff") if isinstance(sources, dict) else None

    redacted_turns = []
    if isinstance(transcript, dict):
        turns = transcript.get("turns", [])
        if isinstance(turns, list):
            for turn in turns:
                if not isinstance(turn, dict):
                    continue
                redacted_turns.append(
                    {
                        "role": turn.get("role"),
                        "step_id": turn.get("step_id"),
                        "timestamp": turn.get("timestamp"),
                    }
                )

    redacted_otel = []
    if isinstance(otel, dict):
        spans = otel.get("spans", [])
        if isinstance(spans, list):
            for span in spans:
                if not isinstance(span, dict):
                    continue
                redacted_otel.append({
                    "name": span.get("name"),
                    "status": span.get("status"),
                    "start_time": span.get("start_time"),
                    "end_time": span.get("end_time"),
                    "trace_id": span.get("trace_id"),
                    "span_id": span.get("span_id"),
                    "parent_span_id": span.get("parent_span_id"),
                })

    redacted_wazuh = []
    if isinstance(wazuh, dict):
        alerts = wazuh.get("alerts", [])
        if isinstance(alerts, list):
            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                redacted_wazuh.append(
                    {
                        "rule_id": alert.get("rule_id"),
                        "timestamp": alert.get("timestamp"),
                        "rule_description": alert.get("rule_description"),
                        "rule_level": alert.get("rule_level"),
                        "rule_groups": alert.get("rule_groups"),
                        "fields": _redact_mapping(alert.get("fields", {}), drop={"tenant", "tenant_id"}),
                    }
                )

    redacted_tool_audit = []
    if isinstance(tool_audit, dict):
        records = tool_audit.get("records", [])
        if isinstance(records, list):
            for record in records:
                if not isinstance(record, dict):
                    continue
                redacted_tool_audit.append(
                    {
                        "tool": record.get("tool"),
                        "decision": record.get("decision"),
                        "arguments_digest": record.get("arguments_digest"),
                        "timestamp": record.get("timestamp"),
                        "policy": record.get("policy"),
                        "span_id": record.get("span_id"),
                    }
                )

    redacted_state = []
    if isinstance(state_diff, dict):
        changes = state_diff.get("changes", [])
        if isinstance(changes, list):
            for change in changes:
                if not isinstance(change, dict):
                    continue
                redacted_state.append(
                    {
                        "collection": change.get("collection"),
                        "operation": change.get("operation"),
                        "count": change.get("count"),
                    }
                )

    return {
        "schema_version": _READ_ONLY_EVIDENCE_SCHEMA,
        "run_id": evidence.get("run_id"),
        "collected_at": evidence.get("collected_at"),
        "window": evidence.get("window"),
        "collector_errors": _redact_mapping(
            {"errors": evidence.get("collector_errors", [])}, drop={"path"}
        ).get("errors", []),
        "sources": {
            "transcript": {
                "turns": redacted_turns,
                "meta": _redact_meta(transcript.get("meta") if isinstance(transcript, dict) else None),
            },
            "otel": {
                "spans": redacted_otel,
                "meta": _redact_meta(otel.get("meta") if isinstance(otel, dict) else None),
            },
            "wazuh": {
                "alerts": redacted_wazuh,
                "meta": _redact_meta(wazuh.get("meta") if isinstance(wazuh, dict) else None),
            },
            "tool_audit": {
                "records": redacted_tool_audit,
                "meta": _redact_meta(
                    tool_audit.get("meta") if isinstance(tool_audit, dict) else None
                ),
            },
            "state_diff": {
                "changes": redacted_state,
                "meta": _redact_meta(
                    state_diff.get("meta") if isinstance(state_diff, dict) else None
                ),
            },
        },
    }


def _serialize_read_only_resource(handler_name: str, value: Any) -> Any:
    if not _read_only_mode():
        return _jsonable(value)

    if handler_name not in _READ_ONLY_RESOURCE_HANDLERS:
        raise AgentSecError(
            f"read-only output policy for resource handler '{handler_name}' is not defined",
            details={"handler": handler_name},
        )

    if handler_name in {
        "list_targets",
        "get_target_schema",
        "list_scenarios",
        "list_findings",
        "coverage",
        "audit_tail",
    }:
        return _jsonable(value)

    if handler_name == "get_run":
        if not isinstance(value, Run):
            raise AgentSecError("read-only run payload is malformed", details={"handler": handler_name})
        return _read_only_run_output(value)

    if handler_name == "get_run_evidence":
        if not isinstance(value, dict):
            raise AgentSecError(
                "read-only evidence payload is malformed", details={"handler": handler_name}
            )
        return _read_only_evidence_output(value)

    raise AgentSecError(
        f"read-only output policy for resource handler '{handler_name}' is incomplete",
        details={"handler": handler_name},
    )


def _jsonable(value: Any) -> Any:
    if isinstance(value, BatchResult):
        # Return the normalised report, not the raw Run objects: the report is
        # already the redacted, stable shape both interfaces consume.
        return value.report
    if _read_only_mode() and isinstance(value, Run):
        return _read_only_run_output(value)
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


@lru_cache(maxsize=32)
def _arg_validator(tool_name: str) -> Draft202012Validator:
    return Draft202012Validator(tool_by_name(tool_name).input_schema)


def validate_arguments(tool: ToolSpec, arguments: dict[str, Any]) -> None:
    """Enforce the declared schema server-side.

    FastMCP derives the client-facing schema from the handler's Python signature,
    which loses the parts that carry the security properties: ``pattern``,
    ``enum``, ``maxItems`` and ``additionalProperties: false``. Advertising a
    constraint is not enforcing it in any case — a client can send whatever it
    likes — so the declared schema in ``mcp/contract.py`` is validated here, at
    the point where it actually binds.
    """
    errors = sorted(_arg_validator(tool.name).iter_errors(arguments), key=str)
    if errors:
        first = errors[0]
        where = "/".join(str(p) for p in first.absolute_path) or "(root)"
        raise AgentSecError(
            f"invalid arguments for {tool.name} at {where}: {first.message}",
            details={"violations": [e.message for e in errors[:5]]},
        )


def _dispatch(service: HarnessService, tool: ToolSpec, arguments: dict[str, Any]) -> Any:
    if _read_only_mode() and not tool.read_only:
        raise AgentSecError(
            f"tool '{tool.name}' is disabled: this gateway runs in read-only mode",
            details={"env": ENV_READ_ONLY},
        )

    validate_arguments(tool, arguments)

    handler = getattr(service, tool.handler, None)
    if handler is None:  # pragma: no cover - guarded by test_mcp_contract
        raise AgentSecError(f"tool '{tool.name}' has no handler '{tool.handler}'")

    return _jsonable(handler(**arguments))


def build_server():  # noqa: ANN201 - FastMCP is an optional import
    """Construct the FastMCP server. Requires the ``mcp`` extra."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover
        raise AgentSecError(
            "the MCP gateway needs the 'mcp' extra: pip install 'agentsec[mcp]'"
        ) from exc

    settings = load_settings()
    service = HarnessService(settings, actor=os.environ.get("AGENTSEC_ACTOR", "mcp"))
    server = FastMCP("agentsec")

    read_only = _read_only_mode()
    active_tools = [tool for tool in TOOLS if (read_only is False or tool.read_only)]
    active_resources = [resource for resource in RESOURCES if (read_only is False or resource.read_only)]

    for tool in active_tools:
        server.add_tool(
            _make_tool_callable(service, tool),
            name=tool.name,
            title=tool.title,
            description=tool.description,
            structured_output=True,
        )

    for resource in active_resources:
        _register_resource(server, service, resource)

    for prompt in PROMPTS:
        _register_prompt(server, prompt)

    return server


_JSON_TO_PY: dict[str, Any] = {
    "string": str,
    "integer": int,
    "number": float,
    "boolean": bool,
    "object": dict,
}


def _annotation_for(spec: dict[str, Any]) -> Any:
    """Python annotation matching a declared JSON Schema property.

    Every parameter is optional at the Python level; ``required`` is enforced by
    ``validate_arguments`` against the declared schema, so there is exactly one
    place that decides what a valid call looks like.
    """
    kind = str(spec.get("type") or "string")
    if kind == "array":
        item_kind = str((spec.get("items") or {}).get("type") or "string")
        inner = _JSON_TO_PY.get(item_kind, str)
        return list[inner] | None  # type: ignore[valid-type]
    if kind == "object":
        return dict[str, Any] | None
    return _JSON_TO_PY.get(kind, str) | None


def _make_tool_callable(service: HarnessService, tool: ToolSpec):  # noqa: ANN202
    """Wrap a service method as an MCP tool.

    Failures are converted into a structured result rather than raised: a
    traceback crossing the protocol boundary would hand the client workspace
    paths and internal structure.
    """
    properties: dict[str, Any] = tool.input_schema.get("properties", {})

    def call(**kwargs: Any) -> dict[str, Any]:
        # Drop unset optionals so a caller passing `scenario_ids=None` is
        # indistinguishable from one that omitted it.
        cleaned = {k: v for k, v in kwargs.items() if v is not None}
        try:
            return {"ok": True, "result": _dispatch(service, tool, cleaned)}
        except AgentSecError as exc:
            service.store.audit(
                actor=service.actor, action=tool.name, outcome="error",
                detail={"code": exc.code, "message": exc.message},
            )
            return {"ok": False, **exc.to_dict()}
        except Exception as exc:
            service.store.audit(
                actor=service.actor, action=tool.name, outcome="internal_error",
                detail={"type": type(exc).__name__},
            )
            return {
                "ok": False,
                "error": "internal_error",
                "message": f"{type(exc).__name__} while handling {tool.name}",
            }

    call.__name__ = tool.name
    call.__doc__ = tool.description
    call.__signature__ = inspect.Signature(  # type: ignore[attr-defined]
        [
            inspect.Parameter(
                name,
                inspect.Parameter.KEYWORD_ONLY,
                default=None,
                annotation=_annotation_for(spec),
            )
            for name, spec in properties.items()
        ],
        return_annotation=dict[str, Any],
    )
    call.__annotations__ = {
        **{name: _annotation_for(spec) for name, spec in properties.items()},
        "return": dict[str, Any],
    }
    return call


def _with_signature(fn, params: list[str]):  # noqa: ANN001, ANN202
    """Give a ``**kwargs`` function an explicit signature.

    FastMCP derives resource and prompt arguments by introspection and rejects a
    bare ``**kwargs``. Since these handlers are generated from data rather than
    written out one per URI, we synthesise the signature instead of hand-writing
    a function per template.
    """
    fn.__signature__ = inspect.Signature(
        [
            inspect.Parameter(p, inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=str)
            for p in params
        ],
        return_annotation=str,
    )
    fn.__annotations__ = {**{p: str for p in params}, "return": str}
    return fn


def _resource_params(uri_template: str) -> list[str]:
    return re.findall(r"\{([a-z_]+)\}", uri_template)


def _register_resource(server, service: HarnessService, resource) -> None:  # noqa: ANN001
    handler_name = resource.handler
    params = _resource_params(resource.uri_template)

    def read(**kwargs: Any) -> str:
        try:
            handler = getattr(service, handler_name, None)
            if handler is None:
                # A few resources are served straight off the store (audit_tail).
                handler = getattr(service.store, handler_name)
            return json.dumps(
                _serialize_read_only_resource(handler_name, handler(**kwargs)),
                indent=2,
                default=str,
            )
        except AgentSecError as exc:
            # Resources cannot signal failure structurally, so return the error
            # body rather than raising through the protocol.
            return json.dumps(exc.to_dict(), indent=2)

    read.__name__ = f"read_{handler_name}"
    read.__doc__ = resource.description

    server.resource(
        resource.uri_template,
        name=resource.title,
        description=resource.description,
        mime_type=resource.mime_type,
    )(_with_signature(read, params))


def _register_prompt(server, prompt) -> None:  # noqa: ANN001
    placeholders = sorted(set(re.findall(r"\{([a-z_]+)\}", prompt.template)))

    def render(**kwargs: Any) -> str:
        # Unfilled placeholders render as <name> so the workflow is still usable
        # when the caller does not know the target id yet.
        values = {p: kwargs.get(p) or f"<{p}>" for p in placeholders}
        return prompt.template.format(**values)

    render.__name__ = prompt.name.replace("-", "_")
    render.__doc__ = prompt.description

    server.prompt(name=prompt.name, title=prompt.title, description=prompt.description)(
        _with_signature(render, placeholders)
    )


def main() -> None:
    """Entry point for ``agentsec-mcp``. Serves over stdio."""
    build_server().run()


if __name__ == "__main__":  # pragma: no cover
    main()
