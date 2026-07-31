"""End-to-end pipeline: policy -> replay -> evidence -> verdict -> report.

These are the tests that would catch a regression in the thing the product
actually promises. They run against the shipped fixture corpus, so they also fail
if a scenario or a fixture drifts out of agreement with the other.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

import pytest

from agentsec.errors import PolicyViolation, RunNotFound
from agentsec.models.finding import FindingStatus
from agentsec.models.run import PurpleVerdict, RunStatus
from agentsec.reporting.junit import render_junit
from agentsec.service.harness import HarnessService
from tests.conftest import REPO_ROOT

#: The verdict matrix the fixture corpus is built to produce. Asserting it here
#: means the README's worked example cannot silently stop being true.
EXPECTED = {
    "AGT-XPIA-001": ("secure", "pass", "pass", "pass", "not_tested"),
    "AGT-TOOLLOOP-001": ("secure", "pass", "pass", "pass", "not_tested"),
    "AGT-TENANT-001": ("prevention_gap", "fail", "pass", "pass", "pass"),
    "AGT-MEMPOIS-001": ("detection_gap", "fail", "fail", "pass", "fail"),
}


def test_full_run_produces_the_expected_verdict_matrix(service: HarnessService) -> None:
    result = service.start_run(target_id="demo-agent-fixture", profile="nightly")
    assert len(result.runs) == 4

    actual = {
        s.scenario_id: (s.verdict, s.prevention, s.detection, s.evidence, s.response)
        for s in result.summaries
    }
    assert actual == EXPECTED


def test_prevention_gap_and_detection_gap_are_distinguished(service: HarnessService) -> None:
    """The distinction is the product. Both scenarios fail prevention; only one
    is invisible to the blue team, and only that one is a detection gap."""
    result = service.start_run(target_id="demo-agent-fixture", profile="nightly")
    by_id = {s.scenario_id: s for s in result.summaries}

    tenant, memory = by_id["AGT-TENANT-001"], by_id["AGT-MEMPOIS-001"]
    assert tenant.prevention == memory.prevention == "fail"
    assert tenant.detection == "pass" and memory.detection == "fail"
    assert tenant.verdict == "prevention_gap"
    assert memory.verdict == "detection_gap"


def test_exit_code_reflects_blocking_findings(service: HarnessService) -> None:
    result = service.start_run(target_id="demo-agent-fixture", profile="nightly")
    assert result.exit_code == 1
    assert set(result.report["blocking_scenarios"]) == {"AGT-TENANT-001", "AGT-MEMPOIS-001"}


def test_secure_only_selection_exits_zero(service: HarnessService) -> None:
    result = service.start_run(
        target_id="demo-agent-fixture",
        scenario_ids=["AGT-XPIA-001", "AGT-TOOLLOOP-001"],
        profile="pr",
    )
    assert result.exit_code == 0
    assert result.report["blocking_count"] == 0


def test_dry_run_executes_nothing_but_records_the_decision(service: HarnessService) -> None:
    result = service.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-XPIA-001"],
        profile="pr", dry_run=True,
    )
    run = result.runs[0]
    assert run.dry_run is True
    assert run.execution is None
    assert run.verdict is None
    assert run.status is RunStatus.COMPLETED
    assert "nothing executed" in (run.refusal_reason or "")


def test_evidence_bundle_is_persisted_and_readable(service: HarnessService) -> None:
    result = service.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-XPIA-001"], profile="pr"
    )
    run = result.runs[0]
    assert run.evidence_ref

    bundle = service.get_run_evidence(run.run_id)
    assert bundle["run_id"] == run.run_id
    assert bundle["sources"]["wazuh"]["alerts"][0]["rule_id"] == "100501"
    assert bundle["sources"]["transcript"]["turns"]


def test_run_records_the_contract_digest(service: HarnessService) -> None:
    """A historical verdict must stay tied to the contract that produced it."""
    result = service.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-XPIA-001"], profile="pr"
    )
    assert result.runs[0].scenario_digest
    assert result.runs[0].scenario_digest.startswith("sha256:")


def test_missing_evidence_file_degrades_to_error_not_pass(
    service: HarnessService, workspace: Path
) -> None:
    """The most dangerous possible bug in a purple harness, pinned down.

    Delete the Wazuh fixture and the detection axis must go to `error`, taking
    the verdict with it. If this ever returns `secure`, the tool is lying.
    """
    (workspace / "fixtures" / "demo-agent" / "AGT-XPIA-001.wazuh.json").unlink()

    result = service.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-XPIA-001"], profile="pr"
    )
    run = result.runs[0]
    assert run.verdict is not None
    assert run.verdict.detection.value == "error"
    assert run.verdict.purple_verdict is PurpleVerdict.ERROR
    assert not run.verdict.is_secure

    summary = result.summaries[0]
    assert any(e["source"] == "wazuh" for e in summary.collector_errors)


def test_missing_fixture_transcript_fails_the_run_not_the_verdict(
    service: HarnessService, workspace: Path
) -> None:
    """An attack that could not run must not manufacture a detection gap."""
    (workspace / "fixtures" / "demo-agent" / "AGT-XPIA-001.transcript.json").unlink()

    result = service.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-XPIA-001"], profile="pr"
    )
    run = result.runs[0]
    assert run.status is RunStatus.FAILED
    assert run.verdict is not None
    assert run.verdict.purple_verdict is PurpleVerdict.ERROR
    assert "fixture" in (run.refusal_reason or "").lower()


# ----------------------------------------------------------------- policy paths


def test_empty_selection_raises_rather_than_reporting_success(
    service: HarnessService,
) -> None:
    """Zero scenarios must not exit 0.

    No scenario in the catalogue opts into the `release` profile, so this
    selection is empty. Reporting "0 runs, no blocking findings" would be a green
    pipeline that tested nothing — the failure mode most likely to go unnoticed
    for months.
    """
    with pytest.raises(PolicyViolation, match="no scenarios selected"):
        service.start_run(target_id="demo-agent-fixture", profile="release")


def test_unknown_target_raises(service: HarnessService) -> None:
    from agentsec.errors import TargetNotFound

    with pytest.raises(TargetNotFound):
        service.start_run(target_id="does-not-exist", profile="pr")


def test_unknown_run_raises(service: HarnessService) -> None:
    with pytest.raises(RunNotFound):
        service.get_run("RUN-19700101-001")


# --------------------------------------------------------------------- findings


def test_non_secure_run_creates_a_finding(service: HarnessService) -> None:
    service.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-MEMPOIS-001"], profile="nightly"
    )
    findings = service.list_findings()
    assert len(findings) == 1
    assert findings[0]["scenario_id"] == "AGT-MEMPOIS-001"
    assert findings[0]["verdict"] == "detection_gap"
    assert findings[0]["status"] == "new"


def test_repeated_failure_updates_one_finding(service: HarnessService) -> None:
    """Otherwise the backlog measures how often CI runs, not how many bugs exist."""
    for _ in range(3):
        service.start_run(
            target_id="demo-agent-fixture", scenario_ids=["AGT-MEMPOIS-001"],
            profile="nightly",
        )
    findings = service.list_findings()
    assert len(findings) == 1
    assert findings[0]["first_seen_run"] != findings[0]["last_seen_run"]


def test_secure_run_creates_no_finding(service: HarnessService) -> None:
    service.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-XPIA-001"], profile="pr"
    )
    assert service.list_findings() == []


def test_finding_cannot_be_verified_without_a_regression_test(
    service: HarnessService,
) -> None:
    from agentsec.errors import InvalidTransition

    service.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-MEMPOIS-001"], profile="nightly"
    )
    fid = service.list_findings()[0]["finding_id"]

    service.promote_finding(finding_id=fid, status="reproduced")
    service.promote_finding(finding_id=fid, status="fixing")
    service.promote_finding(finding_id=fid, status="regression_added")

    # A detection gap additionally needs a detection rule. Closing it with only a
    # code fix leaves the blue side exactly as blind as before.
    with pytest.raises(InvalidTransition, match="detection rule"):
        service.promote_finding(finding_id=fid, status="verified")


def test_detection_gap_verifies_once_both_halves_are_linked(
    service: HarnessService,
) -> None:
    service.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-MEMPOIS-001"], profile="nightly"
    )
    fid = service.list_findings()[0]["finding_id"]

    for status in ("reproduced", "fixing"):
        service.promote_finding(finding_id=fid, status=status)
    service.promote_finding(
        finding_id=fid, status="regression_added",
        regression_test_ref="scenarios/AGT-MEMPOIS-900.yaml",
    )
    service.promote_finding(
        finding_id=fid, status="detection_added", detection_rule_ref="wazuh/100720.xml"
    )
    result = service.promote_finding(finding_id=fid, status="verified")
    assert result["status"] == FindingStatus.VERIFIED


def test_illegal_transition_is_rejected(service: HarnessService) -> None:
    from agentsec.errors import InvalidTransition

    service.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-MEMPOIS-001"], profile="nightly"
    )
    fid = service.list_findings()[0]["finding_id"]
    with pytest.raises(InvalidTransition):
        service.promote_finding(finding_id=fid, status="verified")  # new -> verified


def test_regression_draft_is_blocking_and_linked(service: HarnessService) -> None:
    import yaml

    service.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-TENANT-001"], profile="pr"
    )
    fid = service.list_findings()[0]["finding_id"]
    draft = service.create_regression_draft(finding_id=fid)

    doc = yaml.safe_load(draft["yaml"])
    assert doc["spec"]["regression"]["gate"] == "blocking"
    assert doc["spec"]["regression"]["linked_finding"] == fid
    assert "regression" in doc["metadata"]["tags"]
    assert doc["metadata"]["id"] != "AGT-TENANT-001"
    # Deliberately not written to disk: adding a merge gate is a review event.
    assert not (service.settings.scenarios_dir / f"{doc['metadata']['id']}.yaml").exists()


# ---------------------------------------------------------------------- compare


def test_compare_flags_a_contract_change(service: HarnessService, workspace: Path) -> None:
    """A verdict difference across two different contracts says nothing about the
    system under test, and the comparison must say so."""
    import yaml

    first = service.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-XPIA-001"], profile="pr"
    ).runs[0]

    path = workspace / "scenarios" / "AGT-XPIA-001.yaml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["spec"]["contract"]["detection"]["wazuh"]["must_fire"][0]["rule_id"] = "999999"
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    fresh = HarnessService(service.settings, actor="pytest")
    second = fresh.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-XPIA-001"], profile="pr"
    ).runs[0]

    diff = fresh.compare_runs(run_a=first.run_id, run_b=second.run_id)
    assert diff["contract_changed"] is True
    assert diff["verdict_changed"] is True
    assert diff["axes_changed"]["detection"] == ["pass", "fail"]


def test_compare_identifies_regressed_checks(service: HarnessService) -> None:
    a = service.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-XPIA-001"], profile="pr"
    ).runs[0]
    b = service.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-XPIA-001"], profile="pr"
    ).runs[0]
    diff = service.compare_runs(run_a=a.run_id, run_b=b.run_id)
    assert diff["contract_changed"] is False
    assert diff["verdict_changed"] is False
    assert diff["regressed_checks"] == []


# --------------------------------------------------------------------- reporting


def test_junit_maps_error_to_error_and_blocking_to_failure(
    service: HarnessService, workspace: Path
) -> None:
    """CI must be able to tell "your control broke" from "we could not tell"."""
    (workspace / "fixtures" / "demo-agent" / "AGT-XPIA-001.wazuh.json").unlink()
    result = service.start_run(target_id="demo-agent-fixture", profile="nightly")
    xml = render_junit(result.summaries)

    assert '<error message=' in xml
    assert '<failure message=' in xml
    assert 'errors="1"' in xml


def test_junit_does_not_fail_on_a_warning_gated_scenario(service: HarnessService) -> None:
    import yaml

    path = service.settings.scenarios_dir / "AGT-MEMPOIS-001.yaml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["spec"]["regression"]["gate"] = "warning"
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    fresh = HarnessService(service.settings, actor="pytest")
    result = fresh.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-MEMPOIS-001"], profile="nightly"
    )
    xml = render_junit(result.summaries)
    assert "<failure" not in xml
    assert "NON-BLOCKING detection_gap" in xml
    assert result.exit_code == 0


def test_run_ids_are_claimed_atomically(service: HarnessService) -> None:
    """Two processes on one workspace must not be handed the same id.

    The id used to be derived from MAX(run_id) in Python while `save_run` upserts,
    so a collision silently overwrote the earlier run — losing a run without trace,
    in the component whose job is to be the record.
    """
    day = "20260731"
    minted = [service.store.next_run_id(day) for _ in range(50)]
    assert len(set(minted)) == 50
    assert minted[0] == "RUN-20260731-001"
    assert minted[-1] == "RUN-20260731-050"

    # A second store over the same file continues the sequence rather than restarting.
    from agentsec.store.sqlite import ResultStore

    other = ResultStore(service.settings.db_path)
    assert other.next_run_id(day) == "RUN-20260731-051"
    # Days are independent.
    assert other.next_run_id("20260801") == "RUN-20260801-001"


def test_report_counts_the_latest_run_per_scenario(service: HarnessService) -> None:
    """A rollup over every stored run measures how often CI ran, not what is broken.

    Running the same catalogue twice used to report eight runs, four of them secure,
    and name each blocking scenario twice — while `agentsec://coverage` reported
    four. One database is not allowed to disagree with itself.
    """
    service.start_run(target_id="demo-agent-fixture", profile="nightly")
    service.start_run(target_id="demo-agent-fixture", profile="nightly")

    written = service.generate_report(
        target_id="demo-agent-fixture", profile="nightly", formats=["json"]
    )
    report = json.loads(Path(written["written"]["json"]).read_text(encoding="utf-8"))

    assert report["total_runs"] == 4
    assert report["superseded_runs"] == 4
    assert report["secure"] == 2
    assert report["blocking_count"] == 2
    assert sorted(report["blocking_scenarios"]) == ["AGT-MEMPOIS-001", "AGT-TENANT-001"]
    assert len({r["scenario_id"] for r in report["runs"]}) == len(report["runs"])

    # The store's own histogram is the reference the report has to agree with.
    assert report["verdict_counts"] == service.store.verdict_counts(
        target_id="demo-agent-fixture"
    )


def test_report_filters_by_profile_it_labels(service: HarnessService) -> None:
    """A report headed `profile pr` must not be counting nightly runs."""
    service.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-XPIA-001"], profile="pr"
    )
    service.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-MEMPOIS-001"], profile="nightly"
    )

    def scenarios_in(profile: str | None) -> set[str]:
        written = service.generate_report(
            target_id="demo-agent-fixture", profile=profile, formats=["json"]
        )
        report = json.loads(Path(written["written"]["json"]).read_text(encoding="utf-8"))
        assert report["profile"] == (profile or "all")
        return {r["scenario_id"] for r in report["runs"]}

    assert scenarios_in("pr") == {"AGT-XPIA-001"}
    assert scenarios_in("nightly") == {"AGT-MEMPOIS-001"}
    assert scenarios_in(None) == {"AGT-XPIA-001", "AGT-MEMPOIS-001"}


def test_html_report_renders_the_axis_rollup_and_trend(service: HarnessService) -> None:
    """`axis_counts` was computed and then never rendered.

    The four-axis contract is the product's central idea, so a dashboard that omits
    it while showing verdict totals is showing the least interesting half.
    """
    service.start_run(target_id="demo-agent-fixture", profile="nightly")
    service.start_run(target_id="demo-agent-fixture", profile="nightly")
    written = service.generate_report(
        target_id="demo-agent-fixture", profile="nightly", formats=["html", "json"]
    )
    html = Path(written["written"]["html"]).read_text(encoding="utf-8")
    report = json.loads(Path(written["written"]["json"]).read_text(encoding="utf-8"))

    # Every axis is named, and its counts reach the page rather than staying in JSON.
    for axis in ("Prevention", "Detection", "Evidence", "Response"):
        assert axis in html
    assert "2 not tested" in html, "response has two not_tested scenarios"
    assert "3 pass" in html and "1 fail" in html, "detection is 3 pass / 1 fail"

    # Filters exist and are wired to the data attributes the script reads.
    assert 'data-verdict="blocking"' in html
    assert 'class="run-row"' in html

    # Superseded runs are surfaced as trend rather than silently dropped.
    assert report["superseded_runs"] == 4
    assert report["history"]["AGT-MEMPOIS-001"][-1]["verdict"] == "detection_gap"
    assert 'class="spark"' in html


def test_html_report_is_self_contained(service: HarnessService) -> None:
    """It has to open from a CI artifact zip on a machine with no network."""
    service.start_run(target_id="demo-agent-fixture", profile="nightly")
    written = service.generate_report(
        target_id="demo-agent-fixture", profile="nightly", formats=["html", "json"]
    )
    html = Path(written["written"]["html"]).read_text(encoding="utf-8")

    assert "detection_gap" in html
    assert "OWASP Agentic" in html
    for external in ("<script src=", "http://", "https://", "@import"):
        assert external not in html, f"report references external resource: {external}"

    report = json.loads(Path(written["written"]["json"]).read_text(encoding="utf-8"))
    assert report["exit_code"] == 1


# ------------------------------------------------------------------------ audit


def test_audit_log_records_runs_and_refusals(service: HarnessService) -> None:
    service.start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-XPIA-001"], profile="pr"
    )
    with contextlib.suppress(Exception):
        service.get_target("nope")

    entries = service.store.audit_tail(20)
    actions = {e["action"] for e in entries}
    assert "start_run" in actions
    outcomes = {e["outcome"] for e in entries}
    assert "secure" in outcomes


def test_run_ids_are_sequential_within_a_day(service: HarnessService) -> None:
    ids = [
        service.start_run(
            target_id="demo-agent-fixture", scenario_ids=["AGT-XPIA-001"], profile="pr"
        ).runs[0].run_id
        for _ in range(3)
    ]
    suffixes = [int(i.rsplit("-", 1)[1]) for i in ids]
    assert suffixes == sorted(suffixes)
    assert len(set(suffixes)) == 3


def test_rollup_validates_against_the_published_dashboard_schema(
    service: HarnessService,
) -> None:
    """The versioned contract a Live Artifact is invited to depend on.

    `schemas/dashboard.schema.json` is only a promise if something checks that
    the shipped rollup keeps it. Validating the real corpus rather than a
    hand-written sample means a field that quietly changes type fails here.
    """
    from jsonschema import Draft202012Validator

    from agentsec.reporting.publish import PUBLISH_SCHEMA_VERSION

    schema = json.loads(
        (REPO_ROOT / "schemas" / "dashboard.schema.json").read_text(encoding="utf-8")
    )
    report = service.start_run(target_id="demo-agent-fixture", profile="nightly").report

    errors = sorted(Draft202012Validator(schema).iter_errors(report), key=str)
    assert not errors, [f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message}" for e in errors]
    assert report["schema_version"] == PUBLISH_SCHEMA_VERSION
    # The gate, spelled out: two blocking findings in the shipped corpus.
    assert report["exit_code"] == 1
    assert sorted(report["blocking_scenarios"]) == ["AGT-MEMPOIS-001", "AGT-TENANT-001"]
