"""Promptfoo executor parsing and fail-closed behavior."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from agentsec.execution.base import ExecutionContext
from agentsec.execution.promptfoo import PromptfooExecutor
from agentsec.models.scenario import Scenario
from agentsec.models.target import Adapter, Target
from agentsec.scenario.loader import load_scenario_file
from tests.conftest import REPO_ROOT


def _target() -> Target:
    return Target(
        id="test-target",
        environment="local",
        adapter=Adapter(kind="fixture", fixture_dir="fixtures/demo"),
        allowed_executors=["promptfoo"],
    )


def _context(tmp_path, scenario: Scenario) -> ExecutionContext:
    return ExecutionContext(
        run_id="RUN-20260820-001",
        scenario=scenario,
        scenario_path=None,
        target=_target(),
        raw_dir=tmp_path,
        timeout_seconds=15,
    )


def _mock_promptfoo_run(monkeypatch, payload: str) -> None:
    def _fake_run(args: list[str], *_, **__) -> subprocess.CompletedProcess[str]:
        output_path = args[args.index("-o") + 1]
        Path(output_path).write_text(payload, encoding="utf-8")
        return subprocess.CompletedProcess(args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("agentsec.execution.promptfoo.subprocess.run", _fake_run)


@pytest.fixture
def promptfoo_scenario() -> Scenario:
    return load_scenario_file(REPO_ROOT / "scenarios" / "AGT-XPIA-001.yaml")


@pytest.mark.parametrize(
    ("payload", "expected_roles"),
    [
        (json.dumps({"results": {"results": []}}), []),
        (json.dumps({"results": {"results": [{"prompt": "attack prompt"}]}}), ["user"]),
        (
            json.dumps({
                "results": {"results": [{"prompt": "attack prompt", "response": {"output": "   "}}]}
            }),
            ["user", "assistant"],
        ),
        ("not-json", []),
    ],
)
def test_execute_fails_when_no_non_empty_assistant_output(
    monkeypatch, tmp_path, promptfoo_scenario: Scenario, payload: str, expected_roles: list[str]
) -> None:
    _mock_promptfoo_run(monkeypatch, payload)
    executor = PromptfooExecutor(tmp_path)
    result, transcript = executor.execute(_context(tmp_path, promptfoo_scenario))

    assert result.ok is False
    assert "non-empty assistant output" in (result.error or "")
    assert result.raw_ref == str(tmp_path / "RUN-20260820-001.promptfoo.json")
    assert [turn.role for turn in transcript.turns] == expected_roles
    assert transcript.meta is not None
    assert transcript.meta.collector == "promptfoo"
    assert transcript.meta.backend == "cli"


def test_execute_succeeds_when_assistant_output_exists(
    monkeypatch, tmp_path, promptfoo_scenario: Scenario
) -> None:
    payload = json.dumps(
        {
            "results": {
                "results": [
                    {
                        "prompt": "attack prompt",
                        "response": {"output": "completed safely"},
                    }
                ]
            }
        }
    )
    _mock_promptfoo_run(monkeypatch, payload)
    executor = PromptfooExecutor(tmp_path)
    result, transcript = executor.execute(_context(tmp_path, promptfoo_scenario))

    assert result.ok is True
    assert result.raw_ref == str(tmp_path / "RUN-20260820-001.promptfoo.json")
    assert transcript.meta is not None
    assert transcript.meta.backend == "cli"
    assert [turn.role for turn in transcript.turns] == ["user", "assistant"]
    assert transcript.turns[1].content == "completed safely"


def test_execute_fails_when_a_row_reports_an_error(
    monkeypatch, tmp_path, promptfoo_scenario: Scenario
) -> None:
    payload = json.dumps(
        {
            "results": {
                "results": [
                    {
                        "prompt": "attack prompt",
                        "success": False,
                        "error": "timeout",
                        "response": {"output": "Error: timeout"},
                    }
                ]
            }
        }
    )
    _mock_promptfoo_run(monkeypatch, payload)
    executor = PromptfooExecutor(tmp_path)
    result, transcript = executor.execute(_context(tmp_path, promptfoo_scenario))

    assert result.ok is False
    assert "pf-000" in (result.error or "")
    assert result.raw_ref == str(tmp_path / "RUN-20260820-001.promptfoo.json")
    assert [turn.role for turn in transcript.turns] == ["user"]


def test_execute_fails_when_any_row_fails_even_if_others_succeed(
    monkeypatch, tmp_path, promptfoo_scenario: Scenario
) -> None:
    payload = json.dumps(
        {
            "results": {
                "results": [
                    {
                        "prompt": "good prompt",
                        "response": {"output": "completed safely"},
                    },
                    {
                        "prompt": "bad prompt",
                        "success": False,
                        "error": "timeout",
                        "response": {"output": "Error: timeout"},
                    },
                ]
            }
        }
    )
    _mock_promptfoo_run(monkeypatch, payload)
    executor = PromptfooExecutor(tmp_path)
    result, transcript = executor.execute(_context(tmp_path, promptfoo_scenario))

    assert result.ok is False
    assert "pf-001" in (result.error or "")
    assert result.steps_completed == ["pf-000"]
    assert [turn.role for turn in transcript.turns] == ["user", "assistant", "user"]
    assert transcript.turns[1].content == "completed safely"


@pytest.mark.parametrize(
    "row",
    [
        {"prompt": "attack prompt", "success": True, "response": {"output": "ok"}},
        {"prompt": "attack prompt", "error": None, "response": {"output": "ok"}},
        {"prompt": "attack prompt", "response": {"output": "ok", "error": None}},
    ],
)
def test_falsy_error_fields_are_not_a_failed_row(
    monkeypatch, tmp_path, promptfoo_scenario: Scenario, row: dict[str, object]
) -> None:
    payload = json.dumps({"results": {"results": [row]}})
    _mock_promptfoo_run(monkeypatch, payload)
    executor = PromptfooExecutor(tmp_path)
    result, transcript = executor.execute(_context(tmp_path, promptfoo_scenario))

    assert result.ok is True
    assert [turn.role for turn in transcript.turns] == ["user", "assistant"]
