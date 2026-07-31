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

import pytest

pytest.importorskip("mcp", reason="needs the 'mcp' extra")

from agentsec.config import Settings  # noqa: E402
from agentsec.mcp.contract import FORBIDDEN_PARAM_NAMES, TOOLS  # noqa: E402
from agentsec.mcp.server import ENV_READ_ONLY, build_server  # noqa: E402


def _tools(server) -> dict:  # noqa: ANN001
    return server._tool_manager._tools  # noqa: SLF001


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
