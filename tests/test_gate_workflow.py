"""Execute the reusable gate's shell/Python boundary without a live agent run."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GATE = yaml.safe_load((ROOT / ".github/workflows/agentsec-gate.yml").read_text())
SHA = "a" * 40


def _step(step_id: str) -> dict[str, Any]:
    return next(step for step in GATE["jobs"]["purple"]["steps"] if step.get("id") == step_id)


def _execute(step_id: str, cwd: Path, **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", _step(step_id)["run"]],
        cwd=cwd,
        env={**os.environ, **env},
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("sha", ["main", "v0.5.0", "A" * 40, "a" * 39, "a" * 41])
def test_gate_rejects_nonimmutable_sha_before_exporting_workspace(tmp_path, sha):
    (tmp_path / "consumer").mkdir()
    result = _execute(
        "paths", tmp_path, GITHUB_WORKSPACE=str(tmp_path), CALLER_WORKSPACE=".",
        AGENTSEC_EXPECTED_SHA=sha, GITHUB_ENV=str(tmp_path / "env"),
        GITHUB_OUTPUT=str(tmp_path / "outputs"),
    )
    assert result.returncode != 0
    assert not (tmp_path / "env").exists()


@pytest.mark.parametrize("kind", ["database", "report", "symlink", "file"])
def test_gate_refuses_preexisting_result_state(tmp_path, kind):
    consumer = tmp_path / "consumer"
    consumer.mkdir()
    results = consumer / "results"
    if kind == "symlink":
        results.symlink_to(tmp_path, target_is_directory=True)
    elif kind == "file":
        results.write_text("not a results directory")
    else:
        results.mkdir()
        (results / ("agentsec.db" if kind == "database" else "report-old.json")).write_text("{}")
    result = _execute(
        "paths", tmp_path, GITHUB_WORKSPACE=str(tmp_path), CALLER_WORKSPACE=".",
        AGENTSEC_EXPECTED_SHA=SHA, GITHUB_ENV=str(tmp_path / "env"),
        GITHUB_OUTPUT=str(tmp_path / "outputs"),
    )
    assert result.returncode != 0
    assert not (tmp_path / "env").exists()


def test_gate_sets_database_inside_fresh_selected_workspace(tmp_path):
    root = tmp_path / "consumer" / "agent"
    (root / "results").mkdir(parents=True)
    result = _execute(
        "paths", tmp_path, GITHUB_WORKSPACE=str(tmp_path), CALLER_WORKSPACE="agent",
        AGENTSEC_EXPECTED_SHA=SHA, GITHUB_ENV=str(tmp_path / "env"),
        GITHUB_OUTPUT=str(tmp_path / "outputs"), AGENTSEC_DB="/tmp/historical.db",
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "env").read_text().splitlines() == [
        f"AGENTSEC_WORKSPACE={root}", f"AGENTSEC_DB={root / 'results' / 'agentsec.db'}",
    ]


def test_gate_rejects_newline_in_resolved_symlink_path_before_environment_export(tmp_path):
    consumer = tmp_path / "consumer"
    injected = consumer / "agent\nAGENTSEC_CATALOGUE=workspace"
    injected.mkdir(parents=True)
    (consumer / "safe-name").symlink_to(injected, target_is_directory=True)
    result = _execute(
        "paths", tmp_path, GITHUB_WORKSPACE=str(tmp_path), CALLER_WORKSPACE="safe-name",
        AGENTSEC_EXPECTED_SHA=SHA, GITHUB_ENV=str(tmp_path / "env"),
        GITHUB_OUTPUT=str(tmp_path / "outputs"),
    )
    assert result.returncode != 0
    assert not (tmp_path / "env").exists()


@pytest.fixture
def gate_artifacts(tmp_path):
    """A captured invocation and its generated report, with a stale decoy alongside."""
    python = tmp_path / "agentsec-venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.symlink_to(sys.executable)
    reports = tmp_path / "results" / "reports"
    reports.mkdir(parents=True)
    run = {
        "run_id": "RUN-CURRENT", "scenario_id": "AGT-TEST-001", "target_id": "demo",
        "profile": "pr", "status": "completed", "purple_verdict": "secure", "blocking": False,
        **dict.fromkeys(("prevention", "detection", "evidence", "response"), "pass"),
        "source_provenance": {
            "package_commit": SHA, "catalogue_origin": "builtin", "catalogue_ref": SHA,
        },
    }
    batch = {
        "runs": [run], "target_id": "demo", "profile": "pr", "total_runs": 1,
        "blocking_count": 0, "exit_code": 0,
    }
    (tmp_path / "results" / "agentsec-run.json").write_text(json.dumps(batch))
    report_path = reports / "report-current.json"
    report_path.write_text(json.dumps(batch))
    (reports / "report-zz-stale.json").write_text('{"runs": []}')
    (tmp_path / "results" / "agentsec-report.json").write_text(json.dumps({
        "written": {"json": str(report_path)},
    }))
    return tmp_path, batch, report_path


def _summary(root: Path, **env: str) -> subprocess.CompletedProcess[str]:
    return _execute(
        "summary", root, RUNNER_TEMP=str(root), GITHUB_STEP_SUMMARY=str(root / "summary.md"),
        AGENTSEC_EXPECTED_SHA=SHA, AGENTSEC_TARGET="demo", AGENTSEC_PROFILE="pr",
        CALLER_WORKFLOW_REF="owner/consumer/.github/workflows/ci.yml@refs/heads/main",
        CALLER_WORKFLOW_SHA="b" * 40, **{"RUN_EXIT": "0", **env},
    )


def test_gate_reads_exact_report_and_ignores_caller_python_modules(gate_artifacts):
    root, _, _ = gate_artifacts
    (root / "json.py").write_text("raise SystemExit('consumer module was imported')")
    result = _summary(root)
    assert result.returncode == 0, result.stderr
    assert "AGT-TEST-001" in (root / "summary.md").read_text()


def test_gate_summary_escapes_markdown_and_html_from_run_metadata(gate_artifacts):
    root, batch, report_path = gate_artifacts
    batch["runs"][0]["scenario_id"] = "AGT-TEST-001`|<img>\nrow"
    (root / "results" / "agentsec-run.json").write_text(json.dumps(batch))
    report_path.write_text(json.dumps(batch))
    result = _summary(root)
    assert result.returncode == 0, result.stderr
    summary = (root / "summary.md").read_text()
    assert "AGT-TEST-001&#96;&#124;&lt;img&gt; row" in summary
    assert "<img>" not in summary


@pytest.mark.parametrize("change", ["history", "missing", "duplicate", "altered", "outside"])
def test_gate_refuses_report_that_does_not_match_captured_invocation(gate_artifacts, change):
    root, batch, report_path = gate_artifacts
    report = copy.deepcopy(batch)
    if change == "history":
        report["runs"][0]["run_id"] = "RUN-PREVIOUS"
    elif change == "missing":
        report["runs"] = []
    elif change == "duplicate":
        report["runs"].append(copy.deepcopy(report["runs"][0]))
    elif change == "altered":
        report["runs"][0]["purple_verdict"] = "prevention_gap"
    else:
        outside = root / "outside.json"
        outside.write_text(json.dumps(report))
        (root / "results" / "agentsec-report.json").write_text(json.dumps({
            "written": {"json": str(outside)},
        }))
    report_path.write_text(json.dumps(report))
    result = _summary(root)
    assert result.returncode != 0
    assert (root / "summary.md").read_text() == ""


@pytest.mark.parametrize("change", [
    "empty", "missing_source", "wrong_commit", "workspace_catalogue", "wrong_catalogue_ref",
    "wrong_target", "wrong_profile", "refused", "error", "wrong_count", "wrong_blocking",
    "wrong_exit",
])
def test_gate_refuses_unverified_or_incomplete_batches(gate_artifacts, change):
    root, batch, report_path = gate_artifacts
    run = batch["runs"][0]
    if change == "empty":
        batch["runs"] = []
    elif change == "missing_source":
        run["source_provenance"] = None
    elif change == "wrong_commit":
        run["source_provenance"]["package_commit"] = "b" * 40
    elif change == "workspace_catalogue":
        run["source_provenance"]["catalogue_origin"] = "workspace"
    elif change == "wrong_catalogue_ref":
        run["source_provenance"]["catalogue_ref"] = "b" * 40
    elif change == "wrong_target":
        run["target_id"] = "other"
    elif change == "wrong_profile":
        batch["profile"] = "nightly"
    elif change == "refused":
        run["status"] = "refused"
    elif change == "error":
        run["purple_verdict"] = "error"
    elif change == "wrong_count":
        batch["total_runs"] = 2
    elif change == "wrong_blocking":
        batch["blocking_count"] = 1
    else:
        batch["exit_code"] = 1
    (root / "results" / "agentsec-run.json").write_text(json.dumps(batch))
    report_path.write_text(json.dumps(batch))
    result = _summary(root)
    assert result.returncode != 0
    assert (root / "summary.md").read_text() == ""


def test_gate_verifies_valid_blocking_batch_without_suppressing_verdict(gate_artifacts):
    root, batch, report_path = gate_artifacts
    batch.update(blocking_count=1, exit_code=1)
    batch["runs"][0].update(blocking=True, purple_verdict="prevention_gap")
    (root / "results" / "agentsec-run.json").write_text(json.dumps(batch))
    report_path.write_text(json.dumps(batch))
    result = _summary(root, RUN_EXIT="1")
    assert result.returncode == 0, result.stderr
    assert "prevention_gap" in (root / "summary.md").read_text()


@pytest.mark.parametrize("code", [0, 1, 2, 137])
def test_gate_captures_actual_run_exit_even_on_failure(tmp_path, code):
    # Only a stub process executes: this tests the shell boundary, not an agent run.
    python = tmp_path / "agentsec-venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text(f"#!/bin/sh\nexit {code}\n")
    python.chmod(0o755)
    output = tmp_path / "outputs"
    result = _execute(
        "run", tmp_path, RUNNER_TEMP=str(tmp_path), GITHUB_OUTPUT=str(output),
        AGENTSEC_TARGET="demo", AGENTSEC_PROFILE="pr",
    )
    assert result.returncode == code
    assert output.read_text() == f"exit_code={code}\n"
