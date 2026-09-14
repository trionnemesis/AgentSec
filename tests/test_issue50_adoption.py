"""External installation identity must survive refusal, success and historical export."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree as ET

import pytest

from agentsec import installation
from agentsec.config import load_settings
from agentsec.errors import ConfigError
from agentsec.models.run import Run
from agentsec.reporting.html import render_html_report
from agentsec.reporting.junit import render_junit
from agentsec.reporting.normalizer import normalize_run
from agentsec.reporting.publish import publish
from agentsec.scenario.catalog import ScenarioCatalog
from agentsec.service.harness import HarnessService

COMMIT = "a" * 40


def metadata(monkeypatch, direct, *, imported=True):
    dist = SimpleNamespace(
        version="0.4.3",
        locate_file=lambda _: installation.__file__ if imported else "/other/installation.py",
        read_text=lambda _: json.dumps(direct),
    )
    monkeypatch.setattr(installation, "distribution", lambda _: dist)


def test_installer_commit_is_required_not_the_callers_sha(monkeypatch):
    metadata(monkeypatch, {"vcs_info": {"vcs": "git", "commit_id": COMMIT}})
    assert installation.package_identity(COMMIT) == ("0.4.3", COMMIT)
    with pytest.raises(ConfigError, match="does not match"):
        installation.package_identity("b" * 40)


@pytest.mark.parametrize("direct,imported", [
    ({}, True),
    ({"dir_info": {"editable": True}}, True),
    ({"vcs_info": {"vcs": "git", "commit_id": "main"}}, True),
    ({"vcs_info": {"vcs": "git", "commit_id": COMMIT}}, False),
    ([], True),
])
def test_unverified_or_shadowed_installation_cannot_start(monkeypatch, direct, imported):
    metadata(monkeypatch, direct, imported=imported)
    assert installation.package_identity()[1] is None
    with pytest.raises(ConfigError, match="does not match"):
        installation.package_identity(COMMIT)


@pytest.mark.parametrize("ref", ["main", "v0.4.3", "abc123", "A" * 40, "a" * 40 + "\n"])
def test_gate_identity_does_not_accept_mutable_or_malformed_refs(ref):
    with pytest.raises(ConfigError, match="full lowercase"):
        installation.package_identity(ref)


def test_builtin_mode_refuses_overlay_before_execution(settings, monkeypatch):
    import agentsec.service.harness as harness

    monkeypatch.setattr(harness, "package_identity", lambda _: ("0.4.3", COMMIT))
    service = HarnessService(replace(settings, catalogue_mode="builtin", expected_commit=COMMIT))
    with pytest.raises(ConfigError, match="overlays are not supported"):
        service.start_run(target_id="demo-agent-fixture")
    assert service.list_runs() == []


def test_builtin_mode_does_not_fall_back_to_the_source_checkout(monkeypatch, tmp_path):
    import agentsec.config as config

    monkeypatch.setattr(config, "__file__", str(tmp_path / "src/agentsec/config.py"))
    (tmp_path / "scenarios").mkdir()
    with pytest.raises(ConfigError, match="catalogue is missing"):
        config.package_scenario_dir()


def test_catalogue_mode_is_explicit(workspace, monkeypatch):
    monkeypatch.setenv("AGENTSEC_CATALOGUE", "typo")
    with pytest.raises(ConfigError, match="workspace or builtin"):
        load_settings(workspace)


def test_snapshot_survives_reopen_and_changed_contract(service, settings):
    result = service.start_run(target_id="demo-agent-fixture", profile="nightly")
    snapshots = {r.run_id: r.source_provenance for r in result.runs}
    assert result.exit_code == 1
    assert set(result.report["blocking_scenarios"]) == {"AGT-TENANT-001", "AGT-MEMPOIS-001"}
    original = snapshots[result.runs[0].run_id]
    assert original is not None
    scenario_path = settings.scenarios_dir / "AGT-XPIA-001.yaml"
    scenario_path.write_text(
        scenario_path.read_text().replace("severity: high", "severity: medium")
    )

    reopened = HarnessService(settings)
    assert reopened.catalog.content_digest() != original.catalogue_digest
    exported = reopened.generate_report(target_id="demo-agent-fixture", profile="nightly")
    batch = json.loads(Path(exported["written"]["json"]).read_text())
    for row in batch["runs"]:
        snapshot = snapshots[row["run_id"]]
        assert snapshot is not None
        assert row["source_provenance"] == snapshot.model_dump(mode="json")
        stored = reopened.get_run(row["run_id"])
        assert stored.source_provenance == snapshot
        assert snapshot.scenario_digest == stored.scenario_digest
    published = publish("report", batch)
    assert published["runs"] == batch["runs"]
    html = render_html_report(batch)
    assert original.catalogue_digest in html

    cases = ET.fromstring(render_junit(result.summaries)).findall("testcase")
    assert len(cases) == 4
    for case in cases:  # includes secure cases, not just failures
        props = {p.attrib["name"]: p.attrib["value"] for p in case.findall("properties/property")}
        snapshot = snapshots[props["agentsec.run_id"]]
        assert snapshot is not None
        assert props["agentsec.source.scenario_digest"] == snapshot.scenario_digest
        assert props["agentsec.source.catalogue_digest"] == snapshot.catalogue_digest


def test_legacy_run_is_unknown_even_with_a_current_catalogue(service):
    current = service.start_run(target_id="demo-agent-fixture", scenario_ids=["AGT-XPIA-001"])
    payload = current.runs[0].model_dump(mode="json")
    del payload["source_provenance"]
    legacy = Run.model_validate(payload)
    summary = normalize_run(legacy, service.catalog.get(legacy.scenario_id))
    assert summary.to_dict()["source_provenance"] is None
    assert publish("run", legacy)["run"]["source_provenance"] is None
    assert 'value="unknown"' in render_junit([summary])


def test_refused_and_dry_runs_also_capture_identity(service):
    dry = service.start_run(target_id="demo-agent-fixture", scenario_ids=["AGT-XPIA-001"],
                            dry_run=True)
    assert dry.runs[0].source_provenance is not None
    assert dry.runs[0].execution is None
    # A reviewed scenario whose required approval is absent is refused as before.
    path = service.settings.scenarios_dir / "AGT-XPIA-001.yaml"
    path.write_text(path.read_text().replace(
        "    destructive: false", "    destructive: false\n    requires_approval: true"
    ))
    refused = HarnessService(service.settings).start_run(
        target_id="demo-agent-fixture", scenario_ids=["AGT-XPIA-001"])
    assert refused.runs[0].status == "refused"
    assert refused.runs[0].source_provenance is not None


def test_catalogue_digest_covers_payload_contents_and_is_location_independent(workspace, tmp_path):
    import shutil

    path = workspace / "scenarios/AGT-XPIA-001.yaml"
    import yaml

    body = yaml.safe_load(path.read_text())
    step = body["spec"]["attack"]["steps"][0]
    step.pop("payload")
    step["payload_ref"] = "payload.txt"
    path.write_text(yaml.safe_dump(body))
    payload = path.parent / "payload.txt"
    payload.write_text("first")
    first = ScenarioCatalog.from_dir(path.parent).content_digest()
    other = tmp_path / "other-catalogue"
    shutil.copytree(path.parent, other)
    assert ScenarioCatalog.from_dir(other).content_digest() == first
    payload.write_text("changed")
    assert ScenarioCatalog.from_dir(path.parent).content_digest() != first
