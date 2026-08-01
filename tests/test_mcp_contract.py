"""Architectural constraints on the MCP surface, enforced as tests.

The whole security argument for this design is that the gateway is narrow. A
design document cannot enforce that; a failing build can. Every test here exists
because the corresponding mistake is easy to make and expensive to notice.
"""

from __future__ import annotations

import pytest

from agentsec.mcp.contract import (
    FORBIDDEN_PARAM_NAMES,
    FORBIDDEN_TOOL_NAMES,
    RESOURCES,
    TOOLS,
    contract_summary,
)
from agentsec.mcp.prompts import PROMPTS
from agentsec.service.harness import HarnessService


def test_no_generic_capability_tools() -> None:
    """No shell, SQL, arbitrary-URL or arbitrary-prompt tool may exist.

    Any one of these makes the target allowlist, the approval flow and the audit
    log decorative, because the model can reach the same effects directly.
    """
    names = {t.name for t in TOOLS}
    bare = {n.removeprefix("agentsec_") for n in names}
    offenders = (names | bare) & FORBIDDEN_TOOL_NAMES
    assert not offenders, f"forbidden tool(s) on the MCP surface: {sorted(offenders)}"


def test_no_free_text_locator_parameters() -> None:
    """No tool accepts a URL, SQL string, command, path or credential.

    A tool with a `url` parameter is `call_any_url` wearing a hat: the endpoint
    must come from the operator-owned allowlist, never from the caller.
    """
    for tool in TOOLS:
        params = set(tool.input_schema.get("properties", {}))
        offenders = params & FORBIDDEN_PARAM_NAMES
        assert not offenders, (
            f"tool '{tool.name}' accepts forbidden parameter(s) {sorted(offenders)}; "
            "resolve these server-side from the target allowlist instead"
        )


def test_every_tool_schema_is_closed() -> None:
    """additionalProperties must be false, so callers cannot invent arguments."""
    for tool in TOOLS:
        assert tool.input_schema.get("additionalProperties") is False, (
            f"tool '{tool.name}' has an open input schema"
        )


def test_target_references_are_ids_not_locators() -> None:
    """Wherever a target is named, it is a constrained id pattern."""
    for tool in TOOLS:
        spec = tool.input_schema.get("properties", {}).get("target_id")
        if spec is None:
            continue
        assert spec.get("pattern"), f"tool '{tool.name}' target_id has no pattern"
        assert spec["type"] == "string"


def test_exactly_one_execute_tool() -> None:
    """Only start_run may execute. A second execution path is a second policy hole."""
    executors = [t.name for t in TOOLS if t.risk == "execute"]
    assert executors == ["agentsec_start_run"], executors


def test_execute_tool_requires_confirmation_and_is_not_read_only() -> None:
    start = next(t for t in TOOLS if t.name == "agentsec_start_run")
    assert start.requires_confirmation is True
    assert start.read_only is False


def test_no_tool_mints_approvals() -> None:
    """Approvals must come from a human at the CLI.

    If the gateway could grant an approval, a model would be able to satisfy the
    approval requirement it just triggered, which is the same as not having one.
    """
    for tool in TOOLS:
        assert "approve" not in tool.name, f"tool '{tool.name}' looks like it grants approval"
        assert tool.handler != "grant", tool.name
    assert not hasattr(HarnessService, "grant_approval")


def test_approval_id_is_pattern_constrained() -> None:
    start = next(t for t in TOOLS if t.name == "agentsec_start_run")
    spec = start.input_schema["properties"]["approval_id"]
    assert spec["pattern"] == r"^apr_[0-9a-f]{16}$"


def test_all_handlers_exist_on_the_service() -> None:
    """The gateway may only delegate; it may not implement."""
    for tool in TOOLS:
        assert hasattr(HarnessService, tool.handler), (
            f"tool '{tool.name}' declares handler '{tool.handler}' "
            "which does not exist on HarnessService"
        )


def test_resource_handlers_exist() -> None:
    for resource in RESOURCES:
        on_service = hasattr(HarnessService, resource.handler)
        from agentsec.store.sqlite import ResultStore

        on_store = hasattr(ResultStore, resource.handler)
        assert on_service or on_store, (
            f"resource '{resource.uri_template}' has no handler '{resource.handler}'"
        )


def test_all_resources_use_the_agentsec_scheme() -> None:
    for resource in RESOURCES:
        assert resource.uri_template.startswith("agentsec://"), resource.uri_template


def test_every_resource_names_a_publication_policy_that_exists() -> None:
    """The same check `build_server` makes, in the job that runs without the mcp extra.

    A resource whose output has no policy must fail on the machine of whoever
    added it. Asserting it here as well means the failure does not wait for the
    one CI job that installs the gateway.
    """
    from agentsec.reporting.publish import PUBLISHERS

    for resource in RESOURCES:
        assert resource.publish in PUBLISHERS, (
            f"resource '{resource.uri_template}' names publication policy "
            f"'{resource.publish}', which does not exist"
        )


def test_tool_names_are_namespaced() -> None:
    for tool in TOOLS:
        assert tool.name.startswith("agentsec_"), tool.name


def test_every_tool_has_a_substantive_description() -> None:
    """Descriptions are the model's only guidance on when *not* to use a tool."""
    for tool in TOOLS:
        assert len(tool.description) >= 60, f"tool '{tool.name}' description is too thin"


def test_prompts_do_not_carry_security_controls() -> None:
    """A prompt teaches; it must not be the thing standing between a model and
    a production target. Controls live in schemas and the policy guard."""
    for prompt in PROMPTS:
        lowered = prompt.template.lower()
        assert "http://" not in lowered and "https://" not in lowered, prompt.name
        for secret_ish in ("password", "api_key", "token=", "secret="):
            assert secret_ish not in lowered, f"{prompt.name} mentions {secret_ish}"


def test_contract_summary_is_serialisable() -> None:
    import json

    summary = contract_summary()
    json.dumps(summary)
    assert summary["counts"]["tools"] == len(TOOLS)
    assert summary["counts"]["execute_tools"] == 1


@pytest.mark.parametrize("tool", TOOLS, ids=lambda t: t.name)
def test_required_params_are_declared_properties(tool) -> None:  # noqa: ANN001
    properties = set(tool.input_schema.get("properties", {}))
    required = set(tool.input_schema.get("required", []))
    assert required <= properties, f"tool '{tool.name}' requires undeclared params"


# --------------------------------------------------------------------------
# Server-side argument enforcement
#
# FastMCP derives the client-facing schema from the handler signature, which
# loses `pattern`, `enum`, `maxItems` and `additionalProperties`. Those are the
# parts carrying the security properties, so the declared schema is validated
# again inside the dispatcher. Importing agentsec.mcp.server does not require
# the `mcp` extra — only build_server() does — so these run in the normal suite.
# --------------------------------------------------------------------------


def test_declared_schema_is_enforced_not_merely_advertised() -> None:
    from agentsec.errors import AgentSecError
    from agentsec.mcp.contract import tool_by_name
    from agentsec.mcp.server import validate_arguments

    tool = tool_by_name("agentsec_get_target_schema")

    with pytest.raises(AgentSecError, match="does not match"):
        validate_arguments(tool, {"target_id": "NOT_A_VALID_ID"})

    validate_arguments(tool, {"target_id": "order-agent-staging"})


def test_approval_token_shape_is_enforced() -> None:
    from agentsec.errors import AgentSecError
    from agentsec.mcp.contract import tool_by_name
    from agentsec.mcp.server import validate_arguments

    tool = tool_by_name("agentsec_start_run")
    with pytest.raises(AgentSecError, match="does not match"):
        validate_arguments(
            tool, {"target_id": "demo-agent-fixture", "approval_id": "please-let-me-in"}
        )


def test_undeclared_arguments_are_rejected_by_the_dispatcher() -> None:
    """`additionalProperties: false` binds on the direct (CLI/CI) path.

    Over MCP, FastMCP filters unknown keys out before the handler is reached, so
    an undeclared argument is dropped rather than reported. Either way it cannot
    influence behaviour; this asserts the stricter of the two.
    """
    from agentsec.errors import AgentSecError
    from agentsec.mcp.contract import tool_by_name
    from agentsec.mcp.server import validate_arguments

    with pytest.raises(AgentSecError, match="Additional properties|not allowed"):
        validate_arguments(tool_by_name("agentsec_list_targets"), {"base_url": "http://x"})


def test_missing_required_argument_is_rejected() -> None:
    from agentsec.errors import AgentSecError
    from agentsec.mcp.contract import tool_by_name
    from agentsec.mcp.server import validate_arguments

    with pytest.raises(AgentSecError, match="required"):
        validate_arguments(tool_by_name("agentsec_preview_run"), {})


def test_scenario_id_list_is_bounded() -> None:
    """maxItems stops a caller queuing the entire catalogue a thousand times."""
    from agentsec.errors import AgentSecError
    from agentsec.mcp.contract import tool_by_name
    from agentsec.mcp.server import validate_arguments

    with pytest.raises(AgentSecError):
        validate_arguments(
            tool_by_name("agentsec_preview_run"),
            {"target_id": "demo-agent-fixture",
             "scenario_ids": [f"AGT-X-{i:03d}" for i in range(60)]},
        )


def test_read_only_mode_refuses_execution(service, monkeypatch) -> None:  # noqa: ANN001
    """Deployment option C depends on this: the read-only report gateway must
    not merely discourage execution, it must refuse it."""
    from agentsec.errors import AgentSecError
    from agentsec.mcp.contract import tool_by_name
    from agentsec.mcp.server import ENV_READ_ONLY, _dispatch

    monkeypatch.setenv(ENV_READ_ONLY, "1")

    with pytest.raises(AgentSecError, match="read-only"):
        _dispatch(service, tool_by_name("agentsec_start_run"),
                  {"target_id": "demo-agent-fixture"})

    # Read-only tools still work in that mode.
    result = _dispatch(service, tool_by_name("agentsec_list_targets"), {})
    assert any(t["id"] == "demo-agent-fixture" for t in result)


def test_dispatch_returns_the_normalised_report_not_raw_runs(service) -> None:  # noqa: ANN001
    """A BatchResult carries Run objects; the gateway must hand back the
    already-redacted report shape both interfaces consume."""
    from agentsec.mcp.contract import tool_by_name
    from agentsec.mcp.server import _dispatch

    result = _dispatch(
        service, tool_by_name("agentsec_start_run"),
        {"target_id": "demo-agent-fixture", "scenario_ids": ["AGT-XPIA-001"], "profile": "pr"},
    )
    assert result["exit_code"] == 0
    assert result["runs"][0]["purple_verdict"] == "secure"
