"""The MCP gateway as a client sees it.

`tests/test_mcp_contract.py` asserts properties of the declared contract; this
module asserts that the contract is what actually reaches the wire. The two used
to disagree: FastMCP derives what it advertises and validates from the handler's
Python signature, which loses `pattern`, `enum`, `required` and
`additionalProperties` — so the gateway advertised an open schema while
`mcp/contract.py` declared a closed one.

Skipped unless the `mcp` extra is installed. CI keeps that extra out of the main
test job on purpose, and exercises this module in the gateway job instead.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

import pytest

pytest.importorskip("mcp", reason="needs the 'mcp' extra")

from agentsec.config import Settings  # noqa: E402
from agentsec.mcp.contract import (  # noqa: E402
    FORBIDDEN_PARAM_NAMES,
    RESOURCES,
    TOOLS,
    published_resources,
)
from agentsec.mcp.server import ENV_READ_ONLY, build_server  # noqa: E402
from agentsec.service.harness import HarnessService  # noqa: E402


def _tools(server) -> dict:  # noqa: ANN001
    return server._tool_manager._tools  # noqa: SLF001


def _resources(server) -> set:  # noqa: ANN001
    manager = server._resource_manager  # noqa: SLF001
    return {str(r.uri_template) for r in manager._templates.values()} | {  # noqa: SLF001
        str(r.uri) for r in manager._resources.values()  # noqa: SLF001
    }


@pytest.fixture
def gateway(settings: Settings, monkeypatch):  # noqa: ANN001, ANN201
    monkeypatch.setenv("AGENTSEC_WORKSPACE", str(settings.workspace))
    monkeypatch.delenv(ENV_READ_ONLY, raising=False)
    return build_server()


def test_advertised_schema_is_the_declared_schema(gateway) -> None:  # noqa: ANN001
    """A client is told the truth about what it may send."""
    registered = _tools(gateway)
    assert set(registered) == {t.name for t in TOOLS}

    for spec in TOOLS:
        advertised = registered[spec.name].parameters
        assert advertised == spec.input_schema, spec.name
        assert advertised["additionalProperties"] is False, spec.name
        assert not set(advertised["properties"]) & FORBIDDEN_PARAM_NAMES, spec.name


def test_unknown_arguments_are_refused_not_dropped(gateway) -> None:  # noqa: ANN001
    """An argument the schema forbids used to be discarded in silence.

    Not exploitable — a dropped argument has no effect — but a gateway that
    accepts a smuggled locator with `ok: true` leaves no trace of the attempt,
    and the whole point of the closed schema is that the attempt is visible.
    """
    from pydantic import ValidationError

    arg_model = _tools(gateway)["agentsec_preview_run"].fn_metadata.arg_model
    assert arg_model.model_config.get("extra") == "forbid"

    with pytest.raises(ValidationError) as exc:
        arg_model.model_validate(
            {"target_id": "demo-agent-fixture", "url": "http://attacker.example/x"}
        )
    assert exc.value.errors()[0]["type"] == "extra_forbidden"

    # A well-formed call is untouched.
    assert arg_model.model_validate({"target_id": "demo-agent-fixture"})


def test_read_only_mode_does_not_advertise_execution(
    settings: Settings, monkeypatch  # noqa: ANN001
) -> None:
    """Deployment option C describes execution as absent, not merely denied.

    Refusing at dispatch still lets a model plan around a tool the gateway must
    never provide, and still describes the capability to anyone who lists it.
    """
    monkeypatch.setenv("AGENTSEC_WORKSPACE", str(settings.workspace))
    monkeypatch.setenv(ENV_READ_ONLY, "1")
    registered = set(_tools(build_server()))

    assert registered == {t.name for t in TOOLS if t.read_only}
    for name in (
        "agentsec_start_run",
        "agentsec_promote_finding",
        "agentsec_generate_report",
    ):
        assert name not in registered
    assert "agentsec_preview_run" in registered


def test_full_gateway_serves_every_resource(gateway) -> None:  # noqa: ANN001
    assert _resources(gateway) == {r.uri_template for r in RESOURCES}


def test_report_gateway_serves_only_the_allowlisted_resources(
    settings: Settings, monkeypatch  # noqa: ANN001
) -> None:
    """Read-only is not the question — every resource is a read.

    The question is who holds the other end. Per-run evidence, the audit log and
    the target authoring schema are working surfaces for the people running the
    harness; the report gateway exists for someone outside that team.
    """
    monkeypatch.setenv("AGENTSEC_WORKSPACE", str(settings.workspace))
    monkeypatch.setenv(ENV_READ_ONLY, "1")
    served = _resources(build_server())

    assert served == {r.uri_template for r in published_resources()}
    assert "agentsec://runs/{run_id}/evidence" not in served
    assert "agentsec://audit" not in served
    assert "agentsec://coverage" in served


def test_a_resource_without_a_publication_policy_stops_the_server(
    settings: Settings, monkeypatch  # noqa: ANN001
) -> None:
    """Fail closed, and fail on the machine of whoever added the resource."""
    from dataclasses import replace

    from agentsec.errors import AgentSecError

    monkeypatch.setenv("AGENTSEC_WORKSPACE", str(settings.workspace))
    monkeypatch.setattr(
        "agentsec.mcp.server.RESOURCES",
        (*RESOURCES, replace(RESOURCES[0], uri_template="agentsec://new", publish="none")),
    )
    with pytest.raises(AgentSecError) as exc:
        build_server()
    assert "agentsec://new" in exc.value.message


# -- over a real stdio client ------------------------------------------------


async def _probe(env: dict[str, str], uris: list[str]) -> dict:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=sys.executable, args=["-m", "agentsec.mcp.server"], env=env
    )
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = await session.list_tools()
        resources = await session.list_resources()
        templates = await session.list_resource_templates()
        reads = {
            uri: (await session.read_resource(uri)).contents[0].text  # type: ignore[union-attr]
            for uri in uris
        }
    return {
        "tools": sorted(t.name for t in tools.tools),
        "resources": sorted(str(r.uri) for r in resources.resources)
        + sorted(str(t.uriTemplate) for t in templates.resourceTemplates),
        "reads": reads,
    }


def _stdio(workspace, uris, **extra):  # noqa: ANN001, ANN202
    env = {
        **os.environ,
        "AGENTSEC_WORKSPACE": str(workspace),
        "AGENTSEC_ACTOR": "stdio-smoke",
        **extra,
    }
    env.pop(ENV_READ_ONLY, None)
    env.update(extra)
    return asyncio.run(asyncio.wait_for(_probe(env, uris), timeout=90))


def test_report_gateway_over_stdio_lists_and_reads_only_what_it_should(
    service: HarnessService,
) -> None:
    """The end-to-end shape of deployment option C, spoken over the real protocol.

    In-process assertions can only show that `build_server` did the right thing.
    This shows that what a remote dashboard actually receives — after FastMCP,
    after JSON-RPC, after serialisation — is the sanitised product and not the
    raw store.
    """
    result = service.start_run(target_id="demo-agent-fixture", profile="nightly")
    run_id = result.runs[0].run_id

    probe = _stdio(
        service.settings.workspace,
        ["agentsec://coverage", f"agentsec://runs/{run_id}"],
        AGENTSEC_MCP_READ_ONLY="1",
    )

    # Capability listing: execution is absent, and so are the internal surfaces.
    assert probe["tools"] == sorted(t.name for t in TOOLS if t.read_only)
    assert "agentsec_start_run" not in probe["tools"]
    assert sorted(probe["resources"]) == sorted(
        r.uri_template for r in published_resources()
    )

    coverage = json.loads(probe["reads"]["agentsec://coverage"])
    assert coverage["kind"] == "coverage"
    assert coverage["schema_version"]

    run = json.loads(probe["reads"][f"agentsec://runs/{run_id}"])
    assert run["kind"] == "run"
    assert run["run"]["run_id"] == run_id
    assert run["run"]["verdict"]["purple_verdict"]
    # The projection survived the round trip: no workspace path, no token.
    assert "evidence_ref" not in run["run"]
    assert str(service.settings.workspace) not in probe["reads"][f"agentsec://runs/{run_id}"]


def test_evidence_over_stdio_is_projected_on_the_full_gateway(
    service: HarnessService,
) -> None:
    """The local gateway still serves evidence — projected, not raw.

    Raw bundles stay reachable on the execution host, as files and through the
    CLI. What crosses the protocol is the projection, on both gateways, because
    the difference between them is which URIs exist rather than how carefully
    each one is rendered.
    """
    result = service.start_run(
        target_id="demo-agent-fixture",
        scenario_ids=["AGT-TENANT-001"],
        profile="nightly",
    )
    run_id = result.runs[0].run_id
    uri = f"agentsec://runs/{run_id}/evidence"

    probe = _stdio(service.settings.workspace, [uri])
    body = json.loads(probe["reads"][uri])

    assert uri.replace(run_id, "{run_id}") in probe["resources"]
    assert body["kind"] == "evidence"
    turns = body["sources"]["transcript"]["turns"]
    assert turns, "the fixture transcript should have turns"
    assert all("content" not in turn for turn in turns)
    assert all(turn["content_digest"].startswith("sha256:") for turn in turns)
    # The scenario that leaks tenant B's order id must not leak it here.
    assert "ORD-B-77421" not in probe["reads"][uri]
