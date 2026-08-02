"""The composed project dashboard.

`agentsec://dashboard/latest` is the first resource written to be read by
something outside the team that runs the harness, so the properties worth
testing are the ones a reader cannot check for themselves: that reading it
changes nothing, that the document matches the schema they pinned to, and that
the three planes stay separate.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.errors import AgentSecError
from agentsec.reporting.publish import PublicationInvalid, publish
from agentsec.service.harness import HarnessService

MANIFEST = """\
apiVersion: agentsec.dev/v1alpha1
kind: Project
project_id: demo-project
name: Demo
"""


def _snapshot(root: Path) -> dict[str, tuple[int, float]]:
    """Every file under a tree with its size and mtime."""
    return {
        str(p.relative_to(root)): (p.stat().st_size, p.stat().st_mtime)
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


@pytest.fixture
def dashboard(service: HarnessService) -> dict:
    service.start_run(target_id="demo-agent-fixture", profile="nightly")
    return publish("dashboard", service.dashboard())


# -- the contract a consumer pins to -----------------------------------------


def test_the_dashboard_matches_its_published_schema(dashboard: dict) -> None:
    """`publish` validates, so reaching this point is most of the assertion."""
    assert dashboard["kind"] == "dashboard"
    assert dashboard["schema_version"]
    assert dashboard["redaction"]["policy"]
    assert set(dashboard) == {
        "schema_version", "kind", "generated_at", "project", "purple",
        "skill_assurance", "static_posture", "redaction",
    }


def test_publication_is_refused_when_the_document_does_not_match(
    service: HarnessService,
) -> None:
    """Fail closed: a consumer cannot see a changed shape, but can see an error."""
    document = service.dashboard()
    document["purple"]["verdict_counts"] = "not a mapping"
    with pytest.raises(PublicationInvalid) as exc:
        publish("dashboard", document)
    assert "verdict_counts" in exc.value.message


def test_an_unknown_output_kind_is_still_refused() -> None:
    with pytest.raises(AgentSecError):
        publish("dashboards", {})


# -- reading changes nothing --------------------------------------------------


def test_reading_the_dashboard_writes_no_files(service: HarnessService) -> None:
    """Deliberately not implemented by calling generate_report, which writes two."""
    service.start_run(target_id="demo-agent-fixture", profile="nightly")
    before = _snapshot(service.settings.results_dir)

    for _ in range(3):
        publish("dashboard", service.dashboard())

    assert _snapshot(service.settings.results_dir) == before
    assert list(service.settings.reports_dir.iterdir()) == []


def test_reading_the_dashboard_starts_no_run_and_moves_no_finding(
    service: HarnessService,
) -> None:
    service.start_run(target_id="demo-agent-fixture", profile="nightly")
    runs = {r.run_id for r in service.list_runs()}
    findings = {f["finding_id"]: f["status"] for f in service.list_findings()}

    service.dashboard()

    assert {r.run_id for r in service.list_runs()} == runs
    assert {f["finding_id"]: f["status"] for f in service.list_findings()} == findings


# -- the purple plane is the rollup, unchanged --------------------------------


def test_a_scenario_contributes_its_latest_run_only(service: HarnessService) -> None:
    """The aggregation the report already uses, not a second idea of it."""
    service.start_run(target_id="demo-agent-fixture", scenario_ids=["AGT-XPIA-001"])
    service.start_run(target_id="demo-agent-fixture", scenario_ids=["AGT-XPIA-001"])

    purple = service.dashboard()["purple"]
    assert purple["total_runs"] == 1
    assert purple["superseded_runs"] == 1
    assert list(purple["history"]["AGT-XPIA-001"]) != []


def test_untested_and_errored_axes_are_still_counted_as_themselves(
    dashboard: dict,
) -> None:
    """An axis nobody could check must not round up to a pass on a dashboard."""
    axes = dashboard["purple"]["axis_counts"]
    assert set(axes) == {"prevention", "detection", "evidence", "response"}
    for tally in axes.values():
        assert set(tally) == {"pass", "fail", "not_tested", "error"}
    assert axes["response"]["not_tested"] == 2, "the bundled corpus leaves two untested"


def test_the_blocking_decision_is_carried_verbatim(dashboard: dict) -> None:
    purple = dashboard["purple"]
    assert purple["exit_code"] == 1
    assert sorted(purple["blocking_scenarios"]) == ["AGT-MEMPOIS-001", "AGT-TENANT-001"]


# -- the planes stay apart ----------------------------------------------------


def test_skill_outcomes_never_enter_the_purple_counts(dashboard: dict) -> None:
    """Composition, not merging. A number averaging both answers neither."""
    purple = dashboard["purple"]
    assert set(purple["verdict_counts"]) <= {
        "secure", "prevention_gap", "detection_gap", "evidence_gap", "response_gap", "error",
    }
    assert "skill" not in json.dumps(purple)
    assert dashboard["skill_assurance"]["status"] == "not_tested"


def test_a_workspace_with_a_manifest_is_named(service: HarnessService) -> None:
    (service.settings.workspace / ".agentsec").mkdir(parents=True, exist_ok=True)
    (service.settings.workspace / ".agentsec" / "project.yaml").write_text(MANIFEST)

    project = publish("dashboard", service.dashboard())["project"]
    assert project == {
        "status": "declared",
        "project_id": "demo-project",
        "name": "Demo",
        "surfaces": {
            "skills": 0, "supported_skills": 0, "agents": 0, "hooks": 0,
            "mcp_servers": 0, "problems": 0,
        },
    }


def test_an_uninitialised_workspace_is_named_as_such_rather_than_left_blank(
    dashboard: dict,
) -> None:
    """"We do not know which repository this is" must not render as a clean result."""
    assert dashboard["project"]["status"] == "not_initialised"
    assert "agentsec init" in dashboard["project"]["detail"]
    assert dashboard["skill_assurance"] == {
        "status": "not_tested",
        "reason": "project_not_initialised",
        "detail": "the project has no manifest, so its skills were never located",
    }


def test_a_manifest_that_does_not_load_is_invalid_rather_than_absent(
    service: HarnessService,
) -> None:
    """Distinct states: nobody onboarded this repository, versus onboarding is wrong."""
    (service.settings.workspace / ".agentsec").mkdir(parents=True, exist_ok=True)
    (service.settings.workspace / ".agentsec" / "project.yaml").write_text("project_id: [")

    document = publish("dashboard", service.dashboard())
    assert document["project"]["status"] == "invalid"
    assert document["skill_assurance"]["reason"] == "project_invalid"


def test_skill_assurance_says_which_absence_it_means(service: HarnessService) -> None:
    workspace = service.settings.workspace
    (workspace / ".agentsec").mkdir(parents=True, exist_ok=True)
    (workspace / ".agentsec" / "project.yaml").write_text(MANIFEST)
    skill = workspace / ".claude" / "skills" / "demo" / "SKILL.md"
    skill.parent.mkdir(parents=True)

    assert service.dashboard()["skill_assurance"]["reason"] == "no_skill_surface"

    skill.write_text("---\nname: demo\ndescription: d\n---\n")
    assurance = publish("dashboard", service.dashboard())["skill_assurance"]
    assert assurance["status"] == "not_tested"
    assert assurance["reason"] == "no_evaluator"
    assert assurance["counts"]["supported_skills"] == 1
