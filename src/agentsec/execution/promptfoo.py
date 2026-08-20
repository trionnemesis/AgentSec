"""Promptfoo executor.

Generates a promptfoo config from the scenario, shells out to the promptfoo CLI,
and normalises its JSON output into a transcript. Promptfoo's own assertions are
deliberately *not* used for the verdict: we run it with no asserts and let the
AgentSec evaluator judge the result against the contract, so that swapping
promptfoo for something else does not change any pass/fail.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from agentsec.execution.base import ExecutionContext, make_result
from agentsec.models.evidence import SourceMeta, TranscriptSource, TranscriptTurn
from agentsec.models.run import ExecutionResult
from agentsec.models.target import Target


class PromptfooExecutor:
    name = "promptfoo"

    def __init__(self, workspace: Path) -> None:
        self._workspace = workspace

    def available(self, target: Target) -> tuple[bool, str]:
        if "promptfoo" not in target.allowed_executors:
            return False, f"target '{target.id}' does not allow the promptfoo executor"
        if shutil.which("promptfoo") is None and shutil.which("npx") is None:
            return False, "neither `promptfoo` nor `npx` is on PATH"
        return True, "ready"

    def _command(self, config_path: Path, output_path: Path) -> list[str]:
        base = (
            ["promptfoo"] if shutil.which("promptfoo")
            else ["npx", "--yes", "promptfoo@latest"]
        )
        return [*base, "eval", "-c", str(config_path), "-o", str(output_path), "--no-progress-bar"]

    def build_config(self, ctx: ExecutionContext) -> dict[str, object]:
        """Translate the scenario's messages into a promptfoo config.

        The provider is described by target id only. Resolving that to a real
        endpoint is the provider script's job, so a promptfoo config committed to
        the repo never contains a URL or a token.
        """
        prompts = [
            str(step.payload or "")
            for step in ctx.scenario.spec.attack.steps
            if step.kind == "agent_message"
        ]
        extra = ctx.scenario.spec.attack.config or {}
        return {
            "description": f"AgentSec {ctx.scenario.id}: {ctx.scenario.metadata.title}",
            "prompts": prompts,
            "providers": [
                {
                    "id": extra.get("provider", "exec:agentsec-promptfoo-provider"),
                    "config": {"target_id": ctx.target.id, "run_id": ctx.run_id},
                }
            ],
            # No `assert` blocks on purpose: the contract decides, not promptfoo.
            "tests": [{"vars": {}}],
        }

    def execute(self, ctx: ExecutionContext) -> tuple[ExecutionResult, TranscriptSource]:
        started = datetime.now(UTC)
        config_path = ctx.raw_path("promptfoo.yaml")
        output_path = ctx.raw_path("promptfoo.json")

        import yaml

        config_path.write_text(
            yaml.safe_dump(self.build_config(ctx), sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )

        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                self._command(config_path, output_path),
                capture_output=True,
                text=True,
                timeout=ctx.timeout_seconds,
                cwd=self._workspace,
                check=False,
            )
        except FileNotFoundError:
            return (
                make_result(self.name, started, ok=False, error="promptfoo CLI not found"),
                TranscriptSource(meta=SourceMeta(collector="promptfoo")),
            )
        except subprocess.TimeoutExpired:
            return (
                make_result(
                    self.name, started, ok=False,
                    error=f"promptfoo timed out after {ctx.timeout_seconds}s",
                ),
                TranscriptSource(meta=SourceMeta(collector="promptfoo")),
            )

        if not output_path.is_file():
            tail = (proc.stderr or proc.stdout or "").strip()[-400:]
            return (
                make_result(
                    self.name, started, ok=False,
                    error=f"promptfoo produced no output (exit {proc.returncode}): {tail}",
                ),
                TranscriptSource(meta=SourceMeta(collector="promptfoo")),
            )

        turns = self._parse_output(output_path)
        has_assistant_output = any(
            turn.role == "assistant" and turn.content.strip() for turn in turns
        )
        if not has_assistant_output:
            return (
                make_result(
                    self.name,
                    started,
                    ok=False,
                    error="promptfoo produced no non-empty assistant output",
                    raw_ref=str(output_path),
                ),
                TranscriptSource(
                    turns=turns, meta=SourceMeta(collector="promptfoo", backend="cli")
                ),
            )
        return (
            make_result(
                self.name, started, ok=True,
                steps_completed=[t.step_id for t in turns if t.step_id],
                raw_ref=str(output_path),
            ),
            TranscriptSource(
                turns=turns, meta=SourceMeta(collector="promptfoo", backend="cli")
            ),
        )

    @staticmethod
    def _parse_output(path: Path) -> list[TranscriptTurn]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []

        results = data.get("results", {})
        rows = results.get("results", results) if isinstance(results, dict) else results
        turns: list[TranscriptTurn] = []
        for i, row in enumerate(rows if isinstance(rows, list) else []):
            if not isinstance(row, dict):
                continue
            step_id = f"pf-{i:03d}"
            prompt = row.get("prompt")
            if isinstance(prompt, dict):
                prompt = prompt.get("raw") or prompt.get("display")
            if prompt:
                turns.append(TranscriptTurn(role="user", content=str(prompt), step_id=step_id))
            response = row.get("response")
            output = response.get("output") if isinstance(response, dict) else row.get("output")
            if output is not None:
                turns.append(
                    TranscriptTurn(role="assistant", content=str(output), step_id=step_id)
                )
        return turns
