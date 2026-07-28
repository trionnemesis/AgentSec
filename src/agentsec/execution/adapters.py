"""Target adapters — the only code that talks to the system under test.

Two kinds:

``fixture``  Replays a recorded transcript from disk. This is what makes the
             harness testable in CI with no agent running, and what makes a
             finding reproducible a year later.
``http``     Posts turns to a staging agent's chat endpoint.

Credentials are read from the environment by *name*, resolved here, and never
returned to a caller.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from agentsec.errors import ExecutionFailed
from agentsec.models.evidence import TranscriptTurn
from agentsec.models.target import Target


class TargetAdapter(Protocol):
    def send(
        self, *, step_id: str, message: str, principal: str | None, session: str
    ) -> TranscriptTurn:
        ...

    def close(self) -> None:
        ...


class FixtureAdapter:
    """Replays ``<fixture_dir>/<scenario_id>.transcript.json``.

    The file maps step ids to assistant replies, so a fixture stays valid when
    steps are reordered but breaks loudly when a step is renamed — which is the
    behaviour you want, because a renamed step is a changed test.
    """

    def __init__(self, target: Target, scenario_id: str, workspace: Path) -> None:
        fixture_dir = Path(target.adapter.fixture_dir or "")
        if not fixture_dir.is_absolute():
            fixture_dir = workspace / fixture_dir
        self.path = fixture_dir / f"{scenario_id}.transcript.json"
        if not self.path.is_file():
            raise ExecutionFailed(
                f"no fixture transcript for scenario '{scenario_id}'",
                details={"expected": str(self.path)},
            )
        try:
            self._data: dict[str, Any] = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ExecutionFailed(f"malformed fixture {self.path.name}: {exc}") from exc

        self._replies: dict[str, str] = {
            str(k): str(v) for k, v in (self._data.get("replies") or {}).items()
        }

    def send(
        self, *, step_id: str, message: str, principal: str | None, session: str
    ) -> TranscriptTurn:
        if step_id not in self._replies:
            raise ExecutionFailed(
                f"fixture {self.path.name} has no reply for step '{step_id}'",
                details={"known_steps": sorted(self._replies)},
            )
        return TranscriptTurn(
            role="assistant",
            content=self._replies[step_id],
            step_id=step_id,
            principal=principal,
            timestamp=datetime.now(UTC),
        )

    def close(self) -> None:
        return None


class HttpAdapter:
    """Posts to a staging agent over HTTP.

    Expects ``{"reply": "..."}`` or ``{"content": "..."}``; anything else is
    stringified rather than dropped, because an unexpected response shape is
    itself worth having in the transcript.
    """

    def __init__(self, target: Target) -> None:
        import httpx

        adapter = target.adapter
        headers = {"content-type": "application/json"}
        missing: list[str] = []
        for header, env_name in adapter.headers_from_env.items():
            value = os.environ.get(env_name)
            if value is None:
                missing.append(env_name)
            else:
                headers[header] = value
        if missing:
            raise ExecutionFailed(
                f"target '{target.id}' needs environment variables that are not set: "
                f"{sorted(missing)}"
            )

        self._target = target
        self._url = adapter.base_url.rstrip("/") + "/" + adapter.chat_path.lstrip("/")  # type: ignore[union-attr]
        self._client = httpx.Client(timeout=adapter.timeout_seconds, headers=headers)

    def send(
        self, *, step_id: str, message: str, principal: str | None, session: str
    ) -> TranscriptTurn:
        import httpx

        payload: dict[str, Any] = {"message": message, "session_id": session}
        if principal:
            principal_env = self._target.principals.get(principal)
            if principal_env is None:
                raise ExecutionFailed(
                    f"target '{self._target.id}' does not define principal '{principal}'",
                    details={"known": sorted(self._target.principals)},
                )
            token = os.environ.get(principal_env)
            if token is None:
                raise ExecutionFailed(
                    f"principal '{principal}' maps to unset environment variable "
                    f"{principal_env}"
                )
            payload["principal_token"] = token

        try:
            resp = self._client.post(self._url, json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            # Never echo the payload back: it carries the principal token.
            raise ExecutionFailed(
                f"target request failed at step '{step_id}': {type(exc).__name__}"
            ) from exc

        try:
            body = resp.json()
        except ValueError:
            content = resp.text
        else:
            content = (
                body.get("reply")
                or body.get("content")
                or body.get("output")
                or json.dumps(body, ensure_ascii=False)
            ) if isinstance(body, dict) else json.dumps(body, ensure_ascii=False)

        return TranscriptTurn(
            role="assistant",
            content=str(content),
            step_id=step_id,
            principal=principal,
            timestamp=datetime.now(UTC),
        )

    def close(self) -> None:
        self._client.close()


def build_adapter(target: Target, scenario_id: str, workspace: Path) -> TargetAdapter:
    if target.adapter.kind == "fixture":
        return FixtureAdapter(target, scenario_id, workspace)
    return HttpAdapter(target)
