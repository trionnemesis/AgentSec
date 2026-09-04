"""Regression tests for #69: HTTP 200 error envelopes fail closed."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from agentsec.errors import ExecutionFailed
from agentsec.execution.adapters import HttpAdapter
from agentsec.models.target import Target


def _target() -> Target:
    return Target.model_validate(
        {
            "id": "http-error-envelope",
            "environment": "local",
            "adapter": {
                "kind": "http",
                "base_url": "http://127.0.0.1:9999",
                "chat_path": "/chat",
            },
        }
    )


def _adapter_with_response(body: object) -> HttpAdapter:
    adapter = HttpAdapter(_target())
    response = Mock()
    response.json.return_value = body
    response.raise_for_status.return_value = None
    adapter._client.post = Mock(return_value=response)  # noqa: SLF001 - boundary regression
    return adapter


def _send(adapter: HttpAdapter):
    return adapter.send(
        operation="send_message",
        step_id="message-1",
        principal=None,
        session="session-1",
        payload="hello",
    )


def test_http_200_error_envelope_without_model_output_fails_closed() -> None:
    adapter = _adapter_with_response(
        {"error": "upstream model timeout", "reply": None, "request_id": "req-1"}
    )
    try:
        with pytest.raises(ExecutionFailed, match="no usable model output"):
            _send(adapter)
    finally:
        adapter.close()


def test_http_200_explicit_unsuccessful_envelope_fails_closed() -> None:
    adapter = _adapter_with_response(
        {"success": False, "content": "cached text", "error": "generation failed"}
    )
    try:
        with pytest.raises(ExecutionFailed, match="reported failure"):
            _send(adapter)
    finally:
        adapter.close()


@pytest.mark.parametrize("output_key", ["reply", "content"])
def test_http_200_error_envelope_with_stale_output_fails_closed(
    output_key: str,
) -> None:
    adapter = _adapter_with_response(
        {"error": "upstream model timeout", output_key: "cached text"}
    )
    try:
        with pytest.raises(ExecutionFailed, match="reported failure"):
            _send(adapter)
    finally:
        adapter.close()


def test_http_200_real_reply_remains_valid() -> None:
    adapter = _adapter_with_response({"reply": "I cannot perform that action."})
    try:
        turn = _send(adapter)
    finally:
        adapter.close()

    assert turn.role == "assistant"
    assert turn.content == "I cannot perform that action."
    assert turn.step_id == "message-1"


@pytest.mark.parametrize(
    ("body", "type_name", "leak"),
    [
        (["upstream-marker"], "list", "upstream-marker"),
        (424242, "int", "424242"),
        ("bare-string-marker", "str", "bare-string-marker"),
    ],
)
def test_http_200_non_object_json_body_fails_closed(
    body: object, type_name: str, leak: str
) -> None:
    """A bare list, number or string is not a reply; stringifying it would slip
    past the blank-text guard and become assistant evidence."""
    adapter = _adapter_with_response(body)
    try:
        with pytest.raises(ExecutionFailed, match="non-object JSON body") as exc_info:
            _send(adapter)
    finally:
        adapter.close()
    assert type_name in str(exc_info.value)
    assert leak not in str(exc_info.value)


def test_http_200_non_object_json_body_still_acknowledges_a_driver_operation() -> None:
    """Non-message driver operations keep the stringified fallback: no output
    assertion reads their reply, so a bare acknowledgement is still recorded."""
    target = Target.model_validate(
        {
            "id": "http-driver-ack",
            "environment": "staging",
            "capabilities": ["memory"],
            "adapter": {
                "kind": "http",
                "base_url": "http://127.0.0.1:9999",
                "operations": {
                    "send_message": {"path": "/chat"},
                    "seed_memory": {"path": "/_agentsec/seed/memory"},
                    "cleanup": {"path": "/_agentsec/cleanup"},
                },
            },
        }
    )
    adapter = HttpAdapter(target)
    response = Mock()
    response.json.return_value = ["ack"]
    response.raise_for_status.return_value = None
    adapter._client.post = Mock(return_value=response)  # noqa: SLF001 - boundary regression
    try:
        turn = adapter.send(
            operation="seed_memory",
            step_id="seed-1",
            principal=None,
            session="session-1",
            payload="remember",
        )
    finally:
        adapter.close()
    assert turn.role == "system"
    assert turn.content == '["ack"]'
