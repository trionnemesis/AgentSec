"""Regression tests for #69: HTTP 200 error envelopes fail closed."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from agentsec.errors import ExecutionFailed
from agentsec.execution.adapters import HttpAdapter
from agentsec.models.target import Target


def _target() -> Target:
    return Target.model_validate(
        {
            "apiVersion": "agentsec.dev/v1alpha1",
            "kind": "Target",
            "metadata": {"id": "http-error-envelope", "name": "HTTP error envelope"},
            "spec": {
                "environment": "local",
                "endpoint": "http://127.0.0.1:9999",
                "adapter": {"kind": "http"},
                "evidence": {},
            },
        }
    )


def _response(body: object, *, status_code: int = 200) -> Mock:
    response = Mock()
    response.status_code = status_code
    response.json.return_value = body
    response.text = ""
    response.raise_for_status.return_value = None
    return response


def test_http_200_error_envelope_without_model_output_fails_closed(tmp_path: Path) -> None:
    adapter = HttpAdapter(_target(), tmp_path)
    response = _response({"error": "upstream model timeout", "reply": None, "request_id": "req-1"})

    with patch("agentsec.execution.adapters.httpx.post", return_value=response):
        with pytest.raises(ExecutionFailed, match="no usable model output"):
            adapter.send_message("hello", run_id="run-1")


def test_http_200_explicit_unsuccessful_envelope_fails_closed(tmp_path: Path) -> None:
    adapter = HttpAdapter(_target(), tmp_path)
    response = _response({"success": False, "content": "cached text", "error": "generation failed"})

    with patch("agentsec.execution.adapters.httpx.post", return_value=response):
        with pytest.raises(ExecutionFailed, match="reported failure"):
            adapter.send_message("hello", run_id="run-1")


def test_http_200_real_reply_remains_valid(tmp_path: Path) -> None:
    adapter = HttpAdapter(_target(), tmp_path)
    response = _response({"reply": "I cannot perform that action."})

    with patch("agentsec.execution.adapters.httpx.post", return_value=response):
        result = adapter.send_message("hello", run_id="run-1")

    assert result.ok is True
    assert result.transcript.turns[-1].content == "I cannot perform that action."
