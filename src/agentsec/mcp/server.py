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
from agentsec.mcp.contract import RESOURCES, TOOLS, ResourceSpec, ToolSpec, tool_by_name
from agentsec.mcp.prompts import PROMPTS
from agentsec.models.run import Run
from agentsec.reporting.publish import PUBLISHERS, publish
from agentsec.service.harness import BatchResult, HarnessService

#: Set to "1" to refuse every non-read-only tool. This is the read-only report
#: gateway from deployment option C: a Live Artifact dashboard can be pointed at
#: it safely because execution is not merely discouraged, it is absent.
ENV_READ_ONLY = "AGENTSEC_MCP_READ_ONLY"


def _read_only_mode() -> bool:
    return os.environ.get(ENV_READ_ONLY, "").strip().lower() in {"1", "true", "yes"}


def _jsonable(value: Any) -> Any:
    if isinstance(value, BatchResult):
        # Return the normalised report, not the raw Run objects: the report is
        # already the redacted, stable shape both interfaces consume.
        return publish("report", value.report)
    if isinstance(value, Run):
        # A Run carries evidence_ref, execution.raw_ref and the approval token.
        # Those are workspace paths and a credential, and dumping the model sent
        # all three to whoever called the tool.
        return publish("run", value)
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
    _assert_every_resource_has_a_policy()

    for tool in TOOLS:
        # A read-only gateway does not merely refuse execution, it does not offer
        # it: a tool that is advertised is a tool a model will plan around, and
        # deployment option C describes execution as absent rather than denied.
        if read_only and not tool.read_only:
            continue
        server.add_tool(
            _make_tool_callable(service, tool),
            name=tool.name,
            title=tool.title,
            description=tool.description,
            structured_output=True,
        )
        _publish_declared_schema(server, tool)

    for resource in RESOURCES:
        # Read-only is not the distinction that matters here — every resource is
        # a read. The distinction is who is holding the other end.
        if read_only and not resource.published:
            continue
        _register_resource(server, service, resource)

    for prompt in PROMPTS:
        _register_prompt(server, prompt)

    return server


def _assert_every_resource_has_a_policy() -> None:
    """Refuse to start rather than serve an output nobody has vetted.

    The failure this guards against is a quiet one: someone adds a resource, the
    handler returns a model, and the model is serialised in full because nothing
    objected. Checking at startup rather than on first read means the mistake
    surfaces on the machine of whoever made it.
    """
    missing = sorted(r.uri_template for r in RESOURCES if r.publish not in PUBLISHERS)
    if missing:
        raise AgentSecError(
            "these resources have no publication policy: " + ", ".join(missing),
            details={"known_policies": sorted(PUBLISHERS)},
        )


def _publish_declared_schema(server, tool: ToolSpec) -> None:  # noqa: ANN001
    """Make the wire contract match the declared one.

    FastMCP derives what it advertises, and what it validates, from the handler's
    Python signature. That loses every constraint that carries a security property
    — ``pattern``, ``enum``, ``maxItems``, ``required``, ``additionalProperties`` —
    so the advertised schema said "no required fields, any extra key welcome" while
    ``mcp/contract.py`` said the opposite, and an unknown argument was dropped in
    silence rather than refused.

    Two changes, both against the registered tool:

    * the advertised ``parameters`` become the declared schema, so a client is told
      the truth about ``pattern`` and ``required``;
    * the derived argument model forbids extras, so an unknown key is refused at the
      protocol boundary instead of being quietly discarded.

    The refusal happens before the call reaches ``HarnessService``, so it lands in
    the client's error rather than in ``audit_log``. That is the accepted cost of not
    reaching into FastMCP's dispatch path: a security control that works by patching
    another library's internals fails silently the first time that library moves.
    Everything inside the boundary is still checked by ``validate_arguments``.

    Raises if FastMCP's internals are not the shape expected, because a hardening
    step that quietly did nothing is exactly the failure this project is about.
    """
    registered = server._tool_manager._tools.get(tool.name)  # noqa: SLF001
    if registered is None:  # pragma: no cover - add_tool just succeeded
        raise AgentSecError(f"tool '{tool.name}' vanished from the FastMCP registry")

    registered.parameters = dict(tool.input_schema)

    arg_model = getattr(getattr(registered, "fn_metadata", None), "arg_model", None)
    config = getattr(arg_model, "model_config", None)
    if arg_model is None or config is None:  # pragma: no cover - version drift
        raise AgentSecError(
            "cannot harden the MCP argument model: FastMCP no longer exposes "
            "fn_metadata.arg_model. Refusing to start rather than advertise a "
            "closed schema that is not enforced.",
            details={"tool": tool.name},
        )
    config["extra"] = "forbid"
    arg_model.model_rebuild(force=True)


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


def _register_resource(server, service: HarnessService, resource: ResourceSpec) -> None:  # noqa: ANN001
    handler_name = resource.handler
    params = _resource_params(resource.uri_template)

    def read(**kwargs: Any) -> str:
        try:
            handler = getattr(service, handler_name, None)
            if handler is None:
                # A few resources are served straight off the store (audit_tail).
                handler = getattr(service.store, handler_name)
            # The projection, not the handler, decides what leaves the process.
            body = publish(resource.publish, handler(**kwargs))
            return json.dumps(body, indent=2, default=str)
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
