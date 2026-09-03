"""Target adapters: execute attack steps against live or replayed agent targets."""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import httpx

from agentsec.errors import ExecutionFailed
from agentsec.models.evidence import Transcript, TranscriptTurn
from agentsec.models.target import Target


class AdapterResult:
    """Result of one target operation."""

    def __init__(self, *, ok: bool, transcript: Transcript | None = None, detail: str = "") -> None:
        self.ok = ok
        self.transcript = transcript or Transcript()
        self.detail = detail


class TargetAdapter(ABC):
    def __init__(self, target: Target, workspace: Path) -> None:
        self.target = target
        self.workspace = workspace

    @abstractmethod
    def send_message(self, message: str, *, run_id: str) -> AdapterResult:
        raise NotImplementedError

    def add_mcp_server(self, name: str, config: dict[str, Any], *, run_id: str) -> AdapterResult:
        raise ExecutionFailed("target adapter does not support add_mcp_server")

    def seed_memory(self, content: str, *, run_id: str) -> AdapterResult:
        raise ExecutionFailed("target adapter does not support seed_memory")

    def inject_tool_response(self, tool: str, content: str, *, run_id: str) -> AdapterResult:
        raise ExecutionFailed("target adapter does not support inject_tool_response")

    def assume_identity(self, identity: str, *, run_id: str) -> AdapterResult:
        raise ExecutionFailed("target adapter does not support assume_identity")

    def wait(self, seconds: float, *, run_id: str) -> AdapterResult:
        time.sleep(seconds)
        return AdapterResult(ok=True)


class ReplayAdapter(TargetAdapter):
    """Deterministic adapter backed by fixture transcript files."""

    def __init__(self, target: Target, workspace: Path) -> None:
        super().__init__(target, workspace)
        self._step = 0

    def send_message(self, message: str, *, run_id: str) -> AdapterResult:
        self._step += 1
        fixture = self.workspace / "fixtures" / self.target.metadata.id / f"step-{self._step}.json"
        if not fixture.exists():
            raise ExecutionFailed(f"replay fixture not found: {fixture}")
        try:
            raw = json.loads(fixture.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ExecutionFailed(f"cannot read replay fixture: {exc}") from exc
        transcript = Transcript.model_validate(raw.get("transcript", raw))
        return AdapterResult(ok=True, transcript=transcript, detail="recorded replay")


class HttpAdapter(TargetAdapter):
    """Simple HTTP adapter for a target that accepts a message and returns model output."""

    def send_message(self, message: str, *, run_id: str) -> AdapterResult:
        endpoint = self.target.spec.endpoint
        if not endpoint:
            raise ExecutionFailed("HTTP target has no endpoint")
        try:
            resp = httpx.post(
                endpoint,
                json={"message": message},
                headers={"X-AgentSec-Run-ID": run_id},
                timeout=30,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise ExecutionFailed(f"HTTP target request failed: {type(exc).__name__}") from exc

        try:
            body = resp.json()
        except ValueError:
            content = resp.text
        else:
            if isinstance(body, dict):
                # A transport-level 200 is not proof that the model produced a result.
                # Explicit failure metadata and error-only envelopes must fail closed;
                # serialising them into assistant text can make negative output
                # assertions score a false prevention pass (#69).
                if body.get("success") is False or body.get("ok") is False:
                    raise ExecutionFailed("HTTP target reported failure without a valid model result")
                candidates = (body.get("reply"), body.get("content"), body.get("output"))
                content = next(
                    (value for value in candidates if isinstance(value, str) and value.strip()),
                    "",
                )
                if not content:
                    if body.get("error") is not None or body.get("errors") is not None:
                        raise ExecutionFailed("HTTP target returned an error envelope with no usable model output")
                    raise ExecutionFailed("HTTP target returned no usable model output")
            elif isinstance(body, str):
                content = body
            else:
                raise ExecutionFailed("HTTP target returned no usable model output")

        if not isinstance(content, str) or not content.strip():
            raise ExecutionFailed("HTTP target returned no usable model output")

        transcript = Transcript(
            turns=[
                TranscriptTurn(role="user", content=message),
                TranscriptTurn(role="assistant", content=content),
            ]
        )
        return AdapterResult(ok=True, transcript=transcript, detail="live HTTP target")
