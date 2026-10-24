"""Issue #93: the artifact must connect risks to bounded run evidence honestly."""

from __future__ import annotations

import re
from copy import deepcopy

from agentsec.reporting.html import render_dashboard, render_html_report
from agentsec.reporting.publish import publish
from agentsec.service.harness import HarnessService


def _dashboard_with_runs(service: HarnessService) -> dict:
    service.start_run(target_id="demo-agent-fixture", profile="nightly")
    return publish("dashboard", service.dashboard())


def _one_run(document: dict, scenario_id: str = "AGT-XPIA-001") -> dict:
    return next(run for run in document["purple"]["runs"] if run["scenario_id"] == scenario_id)


def _set_rollup(document: dict, runs: list[dict]) -> None:
    purple = document["purple"]
    purple["runs"] = runs
    purple["total_runs"] = len(runs)
    purple["secure"] = sum(run["purple_verdict"] == "secure" for run in runs)
    purple["blocking_count"] = sum(run["blocking"] for run in runs)
    purple["exit_code"] = 1 if purple["blocking_count"] else 0


def test_empty_error_and_incomplete_results_never_get_a_green_summary(
    service: HarnessService,
) -> None:
    empty_page = render_dashboard(publish("dashboard", service.dashboard()))
    assert "No run verdicts are available" in empty_page
    assert 'class="banner ok"' not in empty_page

    document = _dashboard_with_runs(service)
    error_run = deepcopy(_one_run(document))
    error_run.update(
        status="failed",
        purple_verdict="error",
        prevention="error",
        detection="error",
        evidence="error",
        response="error",
        blocking=False,
    )
    _set_rollup(document, [error_run])
    error_page = render_dashboard(document)
    assert "a non-blocking gap or error" in error_page
    assert "This is not a clean result" in error_page
    assert 'class="banner ok"' not in error_page

    pseudo_secure = deepcopy(error_run)
    pseudo_secure.update(purple_verdict="secure", prevention="pass", detection="pass")
    _set_rollup(document, [pseudo_secure])
    incomplete_page = render_dashboard(document)
    assert "one or more runs are incomplete" in incomplete_page
    assert 'class="banner ok"' not in incomplete_page


def test_nonblocking_warning_is_not_presented_as_clean(service: HarnessService) -> None:
    document = _dashboard_with_runs(service)
    warning = deepcopy(_one_run(document))
    warning.update(
        purple_verdict="evidence_gap",
        evidence="fail",
        blocking=False,
        gate="warning",
    )
    _set_rollup(document, [warning])

    page = render_dashboard(document)

    assert "No blocking findings, but" in page
    assert "non-blocking gap or error" in page
    assert 'class="banner ok"' not in page


def test_every_run_exposes_identity_origin_axes_and_bounded_source(
    service: HarnessService,
) -> None:
    document = _dashboard_with_runs(service)
    recorded = deepcopy(_one_run(document, "AGT-XPIA-001"))
    recorded["response"] = "not_tested"
    live = deepcopy(_one_run(document, "AGT-TOOLLOOP-001"))
    live["provenance"]["evidence"] = "live"
    mixed = deepcopy(_one_run(document, "AGT-TENANT-001"))
    mixed["provenance"]["evidence"] = "mixed"
    _set_rollup(document, [recorded, live, mixed])

    page = render_dashboard(document)

    for run in (recorded, live, mixed):
        assert run["run_id"] in page
        assert f'id="run-{run["run_id"]}"' in page
        assert run["source_provenance"]["scenario_digest"] in page
    for origin in ("recorded", "live", "mixed"):
        assert f"origin {origin}" in page
    assert "Four-axis result" in page
    assert "not_tested" in page
    assert "All asserted checks held" in page  # secure runs have evidence detail too


def test_verified_risk_links_to_every_target_run_and_names_a_missing_run(
    service: HarnessService,
) -> None:
    document = _dashboard_with_runs(service)
    gap_run = deepcopy(_one_run(document, "AGT-TENANT-001"))
    gap_run["blocking"] = False
    other_target_run = deepcopy(gap_run)
    other_target_run["run_id"] = "RUN-20261024-999"
    other_target_run["target_id"] = "second-staging-target"
    _set_rollup(document, [gap_run, other_target_run])
    document["repo_risk"] = {
        "status": "inspected",
        "counts": {
            "total": 1,
            "by_severity": {"high": 1},
            "by_verification": {"verified": 1},
        },
        "verify_queue": [],
        "risks": [
            {
                "id": "RISK-1",
                "rule_id": "ASI-TEST-RISK",
                "severity": "high",
                "surface_kind": "tool_grant",
                "file": ".claude/settings.json",
                "title": "Broad tool grant",
                "verification": {
                    "state": "verified",
                    "scenario_ids": [gap_run["scenario_id"], "AGT-MISSING-999"],
                },
            }
        ],
    }

    page = render_dashboard(document)

    assert re.search(r'class="pill skip">\s*verdict available', page)
    assert not re.search(r'class="pill pass">\s*verdict available', page)
    for run in (gap_run, other_target_run):
        assert f'href="#scenario-{run["scenario_id"]}-{run["run_id"]}"' in page
        assert f'href="#run-{run["run_id"]}"' in page
        assert f"on <code>{run['target_id']}</code>" in page
        assert page.count(f'id="scenario-{run["scenario_id"]}-{run["run_id"]}"') == 1
    assert f'data-show-scenario="{gap_run["scenario_id"]}"' in page
    assert "AGT-MISSING-999" in page
    assert "no displayed run" in page
    assert 'document.querySelectorAll("[data-show-scenario]")' in page
    assert 'target.hidden = false' in page


def test_published_strings_are_escaped_and_no_evidence_locator_is_added(
    service: HarnessService,
) -> None:
    document = _dashboard_with_runs(service)
    run = deepcopy(_one_run(document))
    run["scenario_title"] = "</code><script>alert('run')</script>"
    run["rationale"] = "<img src=x onerror=alert(1)>"
    _set_rollup(document, [run])

    page = render_dashboard(document)

    assert "<script>alert('run')</script>" not in page
    assert "&lt;script&gt;alert" in page
    assert "<img src=x" not in page
    assert "evidence_ref" not in page
    assert "http://" not in page and "https://" not in page


def test_dashboard_names_the_intended_live_artifact_consumer(
    service: HarnessService,
) -> None:
    page = render_dashboard(publish("dashboard", service.dashboard()))
    assert "Claude Code Live Artifact" in page
    assert "renderer snapshot, not a Claude Code client" in page


def test_standalone_report_uses_the_same_honest_summary_and_origin(
    service: HarnessService,
) -> None:
    empty_batch = service.dashboard()["purple"]
    empty_page = render_html_report(empty_batch)
    assert "No run verdicts are available" in empty_page
    assert 'class="banner ok"' not in empty_page

    document = _dashboard_with_runs(service)
    run = deepcopy(_one_run(document))
    _set_rollup(document, [run])
    page = render_html_report(document["purple"])
    assert run["run_id"] in page
    assert "origin recorded" in page
    assert run["source_provenance"]["scenario_digest"] in page
    assert "secure</code> for their asserted axes" in page
    assert "Check each run's origin" in page
