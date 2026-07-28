"""Replay executor — deterministic, step-by-step attack playback.

This is the default executor and the one CI should rely on. Every step is
fixed text: no sampling, no generated adversarial prompts, no variance between
runs. When a replay scenario changes verdict, the *system* changed, which is the
only signal a merge gate can act on.

Fuzzier executors (promptfoo, PyRIT) belong in nightly, where a flaky result
costs a triage ticket rather than a blocked release.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

from agentsec.errors import ExecutionFailed
from agentsec.execution.adapters import build_adapter
from agentsec.execution.base import ExecutionContext, make_result
from agentsec.models.evidence import SourceMeta, TranscriptSource, TranscriptTurn
from agentsec.models.run import ExecutionResult
from agentsec.models.target import Target
from agentsec.scenario.loader import resolve_payload


class ReplayExecutor:
    name = "replay"

    def __init__(self, workspace: Path) -> None:
        self._workspace = workspace

    def available(self, target: Target) -> tuple[bool, str]:
        if "replay" not in target.allowed_executors:
            return False, f"target '{target.id}' does not allow the replay executor"
        return True, "ready"

    def execute(self, ctx: ExecutionContext) -> tuple[ExecutionResult, TranscriptSource]:
        started = datetime.now(UTC)
        turns: list[TranscriptTurn] = []
        completed: list[str] = []
        deadline = time.monotonic() + ctx.timeout_seconds
        adapter = build_adapter(ctx.target, ctx.scenario.id, self._workspace)
        current_principal: str | None = None

        try:
            for step in ctx.scenario.spec.attack.steps:
                if time.monotonic() > deadline:
                    raise ExecutionFailed(
                        f"scenario timed out after {ctx.timeout_seconds}s at step '{step.id}'"
                    )

                principal = step.as_principal or current_principal

                if step.kind == "assume_identity":
                    current_principal = step.as_principal
                    turns.append(
                        TranscriptTurn(
                            role="system",
                            content=f"switch principal -> {step.as_principal}",
                            step_id=step.id,
                            principal=step.as_principal,
                            timestamp=datetime.now(UTC),
                        )
                    )
                    completed.append(step.id)
                    continue

                if step.kind == "wait":
                    time.sleep(min(step.seconds or 0, max(0.0, deadline - time.monotonic())))
                    completed.append(step.id)
                    continue

                if step.kind == "snapshot_state":
                    # The state-diff collector reads the baseline itself; the step
                    # exists so the transcript records *when* it was taken.
                    turns.append(
                        TranscriptTurn(
                            role="system",
                            content="state snapshot marker",
                            step_id=step.id,
                            timestamp=datetime.now(UTC),
                        )
                    )
                    completed.append(step.id)
                    continue

                payload = self._payload_for(ctx, step.payload, step.payload_ref)

                if step.kind in {"seed_resource", "seed_memory", "tool_response_injection"}:
                    # Seeding is modelled as a system turn carrying the injected
                    # content. A real deployment wires these to the target's
                    # ingest API; recording them keeps the transcript complete
                    # either way.
                    turns.append(
                        TranscriptTurn(
                            role="system",
                            content=f"[{step.kind}] {payload}",
                            step_id=step.id,
                            principal=principal,
                            timestamp=datetime.now(UTC),
                        )
                    )
                    completed.append(step.id)
                    continue

                # agent_message
                turns.append(
                    TranscriptTurn(
                        role="user",
                        content=payload,
                        step_id=step.id,
                        principal=principal,
                        timestamp=datetime.now(UTC),
                    )
                )
                reply = adapter.send(
                    step_id=step.id,
                    message=payload,
                    principal=principal,
                    session=ctx.run_id,
                )
                turns.append(reply)
                completed.append(step.id)

        except ExecutionFailed as exc:
            return (
                make_result(self.name, started, ok=False, steps_completed=completed,
                            error=exc.message),
                TranscriptSource(turns=turns, meta=self._meta(ctx)),
            )
        finally:
            adapter.close()

        return (
            make_result(self.name, started, ok=True, steps_completed=completed),
            TranscriptSource(turns=turns, meta=self._meta(ctx)),
        )

    @staticmethod
    def _meta(ctx: ExecutionContext) -> SourceMeta:
        return SourceMeta(collector="replay", backend=ctx.target.adapter.kind)

    def _payload_for(
        self, ctx: ExecutionContext, payload: object, payload_ref: str | None
    ) -> str:
        if payload_ref:
            if ctx.scenario_path is None:
                raise ExecutionFailed("payload_ref used but the scenario has no source path")
            return resolve_payload(ctx.scenario_path, payload_ref)
        if payload is None:
            return ""
        if isinstance(payload, str):
            return payload
        import json

        return json.dumps(payload, ensure_ascii=False)
