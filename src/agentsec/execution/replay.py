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
from agentsec.execution.adapters import TargetAdapter, build_adapter
from agentsec.execution.base import ExecutionContext, make_result
from agentsec.models.evidence import SourceMeta, TranscriptSource, TranscriptTurn
from agentsec.models.run import ExecutionResult
from agentsec.models.scenario import driver_operation_for_step_kind
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
        adapter: TargetAdapter | None = None
        current_principal: str | None = None
        failure: str | None = None
        cleanup_error: str | None = None
        close_error: str | None = None

        try:
            adapter = build_adapter(ctx.target, ctx.scenario.id, self._workspace)
            for step in ctx.scenario.spec.attack.steps:
                if time.monotonic() > deadline:
                    raise ExecutionFailed(
                        f"scenario timed out after {ctx.timeout_seconds}s at step '{step.id}'"
                    )

                principal = step.as_principal or current_principal

                if step.kind == "wait":
                    time.sleep(min(step.seconds or 0, max(0.0, deadline - time.monotonic())))
                    # ``wait`` is intentionally executor-local, but retaining
                    # its completed marker preserves the execution contract;
                    # target-driver steps are only marked after ``send``.
                    completed.append(step.id)
                    continue

                payload = self._payload_for(ctx, step.payload, step.payload_ref)
                operation = driver_operation_for_step_kind(step.kind)
                if operation is None:
                    raise ExecutionFailed(f"unsupported step kind '{step.kind}'")

                if operation == "send_message":
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
                    operation=operation,
                    step_id=step.id,
                    payload=payload,
                    principal=principal,
                    session=ctx.run_id,
                )
                turns.append(reply)
                completed.append(step.id)
                if operation == "assume_identity":
                    current_principal = step.as_principal

        except ExecutionFailed as exc:
            failure = exc.message
        except Exception as exc:  # noqa: BLE001
            failure = f"{type(exc).__name__}: {exc}"
        finally:
            if adapter is not None:
                cleanup_error = self._cleanup(adapter, ctx)
                try:
                    adapter.close()
                except ExecutionFailed as exc:
                    close_error = exc.message
                except Exception as exc:  # noqa: BLE001
                    close_error = f"{type(exc).__name__}: {exc}"

        if failure is None and cleanup_error is not None:
            failure = f"run completed, but cleanup failed: {cleanup_error}"
        elif failure is not None and cleanup_error is not None:
            failure = f"{failure}; cleanup failed: {cleanup_error}"
        if close_error is not None:
            failure = (
                f"{failure}; client close failed: {close_error}"
                if failure is not None
                else f"client close failed: {close_error}"
            )

        if failure is not None:
            return (
                make_result(
                    self.name,
                    started,
                    ok=False,
                    steps_completed=completed,
                    error=failure,
                ),
                TranscriptSource(turns=turns, meta=self._meta(ctx)),
            )

        return (
            make_result(self.name, started, ok=True, steps_completed=completed),
            TranscriptSource(turns=turns, meta=self._meta(ctx)),
        )

    @staticmethod
    def _meta(ctx: ExecutionContext) -> SourceMeta:
        return SourceMeta(collector="replay", backend=ctx.target.adapter.kind)

    def _payload_for(
        self,
        ctx: ExecutionContext,
        payload: object,
        payload_ref: str | None,
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

    def _cleanup(self, adapter: TargetAdapter, ctx: ExecutionContext) -> str | None:
        try:
            adapter.cleanup(target_id=ctx.target.id, session=ctx.run_id)
        except ExecutionFailed as exc:
            return exc.message
        except Exception as exc:  # noqa: BLE001
            return f"{type(exc).__name__}: {exc}"
        return None
