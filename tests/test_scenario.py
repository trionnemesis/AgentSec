"""Scenario schema, validator and catalogue."""

from __future__ import annotations

import json

import pytest
import yaml

from agentsec.config import package_schema_dir
from agentsec.errors import ScenarioError
from agentsec.models.scenario import Scenario
from agentsec.scenario.catalog import OWASP_AGENTIC_TOP10, ScenarioCatalog
from agentsec.scenario.loader import load_scenario_file, resolve_payload, scenario_digest
from agentsec.scenario.validator import validate_scenario, validate_scenario_dict
from tests.conftest import REPO_ROOT

SCENARIO_DIR = REPO_ROOT / "scenarios"


def _minimal(**spec_overrides) -> dict:  # noqa: ANN003
    doc = {
        "apiVersion": "agentsec.dev/v1",
        "kind": "Scenario",
        "metadata": {"id": "AGT-TEST-001", "title": "A minimal test scenario", "severity": "low"},
        "spec": {
            "target": {"environments": ["local"]},
            "risk": {"level": "low"},
            "attack": {
                "executor": "replay",
                "steps": [{"id": "go", "kind": "agent_message", "payload": "hello"}],
            },
            "contract": {
                "prevention": {"must_not": [{"kind": "output_contains", "value": "secret"}]},
                "detection": {"wazuh": {"must_fire": [{"rule_id": "100001"}]}},
            },
        },
    }
    doc["spec"].update(spec_overrides)
    return doc


# ------------------------------------------------------------- shipped catalogue


def test_every_shipped_scenario_parses_and_validates() -> None:
    catalog = ScenarioCatalog.from_dir(SCENARIO_DIR, strict=True)
    assert len(catalog) == 4
    assert not catalog.load_errors
    for entry in catalog:
        report = validate_scenario(entry.scenario)
        assert report.ok, [i.render() for i in report.errors]


def test_shipped_scenarios_match_the_json_schema() -> None:
    for path in sorted(SCENARIO_DIR.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        report = validate_scenario_dict(raw)
        assert report.ok, f"{path.name}: {[i.render() for i in report.errors]}"


def test_json_schema_files_are_valid_draft_2020_12() -> None:
    from jsonschema import Draft202012Validator

    for path in sorted(package_schema_dir().glob("*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)


def test_owasp_coverage_denominator_is_the_full_top_ten() -> None:
    """Coverage must be measured against all ten categories.

    Reporting "100% of the categories we happen to have scenarios for" is the
    kind of metric that gets a programme cancelled after an incident.
    """
    catalog = ScenarioCatalog.from_dir(SCENARIO_DIR)
    coverage = catalog.coverage()
    assert coverage["total_categories"] == 10
    assert len(OWASP_AGENTIC_TOP10) == 10
    assert coverage["covered_categories"] == 4
    assert coverage["coverage_ratio"] == pytest.approx(0.4)


# ---------------------------------------------------------------- semantic rules


def test_contract_with_no_assertions_is_an_error() -> None:
    """A scenario that asserts nothing would report secure forever."""
    doc = _minimal()
    doc["spec"]["contract"] = {}
    report = validate_scenario(Scenario.model_validate(doc))
    assert not report.ok
    assert any(i.code == "empty_contract" for i in report.errors)


def test_prevention_only_scenario_warns_red_only() -> None:
    """The core purple argument, enforced at authoring time."""
    doc = _minimal()
    doc["spec"]["contract"] = {
        "prevention": {"must_not": [{"kind": "output_contains", "value": "secret"}]}
    }
    report = validate_scenario(Scenario.model_validate(doc))
    codes = [i.code for i in report.warnings]
    assert "red_only" in codes


def test_scenario_with_no_stimulus_warns() -> None:
    doc = _minimal()
    doc["spec"]["attack"]["steps"] = [{"id": "snap", "kind": "snapshot_state"}]
    report = validate_scenario(Scenario.model_validate(doc))
    assert "no_stimulus" in [i.code for i in report.warnings]


def test_sensitive_data_without_approval_is_an_error() -> None:
    doc = _minimal()
    doc["spec"]["risk"] = {"level": "low", "data_classes_touched": ["pii"]}
    report = validate_scenario(Scenario.model_validate(doc))
    assert any(i.code == "sensitive_data_without_approval" for i in report.errors)


def test_multi_tenant_scenario_with_one_principal_warns() -> None:
    doc = _minimal()
    doc["spec"]["target"] = {"environments": ["local"], "capabilities": ["multi_tenant"]}
    report = validate_scenario(Scenario.model_validate(doc))
    assert "single_principal_tenancy_test" in [i.code for i in report.warnings]


def test_unmapped_scenario_reports_info() -> None:
    report = validate_scenario(Scenario.model_validate(_minimal()))
    assert "unmapped_scenario" in [i.code for i in report.issues]


def test_wait_step_without_seconds_is_an_error() -> None:
    doc = _minimal()
    doc["spec"]["attack"]["steps"].append({"id": "hold", "kind": "wait"})
    report = validate_scenario(Scenario.model_validate(doc))
    assert any(i.code == "wait_without_seconds" for i in report.errors)


def test_duplicate_step_ids_rejected_at_parse_time() -> None:
    doc = _minimal()
    doc["spec"]["attack"]["steps"] = [
        {"id": "go", "kind": "agent_message", "payload": "a"},
        {"id": "go", "kind": "agent_message", "payload": "b"},
    ]
    with pytest.raises(Exception, match="duplicate step ids"):
        Scenario.model_validate(doc)


# ------------------------------------------------------------- target fit checks


def test_assertion_without_a_backend_is_an_error(tmp_path) -> None:  # noqa: ANN001
    """The quietest failure mode: asserting on evidence nobody collects.

    Without this check the axis silently degrades and the dashboard shows a gap
    that is really a plumbing problem.
    """
    from agentsec.models.target import Target

    target = Target.model_validate(
        {
            "id": "no-siem-agent",
            "environment": "local",
            "capabilities": ["rag", "tool_calling", "email"],
            "adapter": {"kind": "fixture", "fixture_dir": "x"},
            "evidence": {"wazuh": {"kind": "none"}},
        }
    )
    scenario = load_scenario_file(SCENARIO_DIR / "AGT-XPIA-001.yaml")
    report = validate_scenario(scenario, target=target)
    codes = [i.code for i in report.errors]
    assert "detection_backend_missing" in codes
    assert "evidence_backend_missing" in codes


def test_environment_mismatch_is_reported() -> None:
    from agentsec.models.target import Target

    doc = _minimal()
    doc["spec"]["target"] = {"environments": ["staging"]}
    scenario = Scenario.model_validate(doc)
    target = Target.model_validate(
        {
            "id": "local-only",
            "environment": "local",
            "adapter": {"kind": "fixture", "fixture_dir": "x"},
            "evidence": {"wazuh": {"kind": "file", "path": "w.json"}},
        }
    )
    report = validate_scenario(scenario, target=target)
    assert any(i.code == "environment_mismatch" for i in report.errors)


# --------------------------------------------------------------------- loader


def test_payload_ref_cannot_escape_the_scenario_directory(tmp_path) -> None:  # noqa: ANN001
    """Scenario packs get shared. A traversal must not read the host's files."""
    scenario_path = tmp_path / "pack" / "AGT-TEST-001.yaml"
    scenario_path.parent.mkdir(parents=True)
    scenario_path.write_text("{}", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("secret", encoding="utf-8")

    with pytest.raises(ScenarioError, match="escapes the scenario directory"):
        resolve_payload(scenario_path, "../outside.txt")


def test_payload_ref_reads_a_sibling_file(tmp_path) -> None:  # noqa: ANN001
    scenario_path = tmp_path / "AGT-TEST-001.yaml"
    scenario_path.write_text("{}", encoding="utf-8")
    (tmp_path / "payload.txt").write_text("injected", encoding="utf-8")
    assert resolve_payload(scenario_path, "payload.txt") == "injected"


def test_yaml_loading_refuses_python_object_construction(tmp_path) -> None:  # noqa: ANN001
    """Scenario files are attacker-adjacent by nature."""
    path = tmp_path / "AGT-EVIL-001.yaml"
    path.write_text("!!python/object/apply:os.system ['echo pwned']\n", encoding="utf-8")
    with pytest.raises(ScenarioError):
        load_scenario_file(path)


def test_scenario_digest_is_order_independent() -> None:
    a = Scenario.model_validate(_minimal())
    doc = _minimal()
    doc["spec"]["risk"] = {"destructive": False, "level": "low"}  # reordered keys
    b = Scenario.model_validate(doc)
    assert scenario_digest(a) == scenario_digest(b)


def test_scenario_digest_changes_with_the_contract() -> None:
    a = Scenario.model_validate(_minimal())
    doc = _minimal()
    doc["spec"]["contract"]["detection"]["wazuh"]["must_fire"][0]["rule_id"] = "999999"
    assert scenario_digest(a) != scenario_digest(Scenario.model_validate(doc))


# -------------------------------------------------------------------- catalogue


def test_catalog_collects_errors_without_hiding_good_scenarios(tmp_path) -> None:  # noqa: ANN001
    import shutil

    shutil.copy(SCENARIO_DIR / "AGT-XPIA-001.yaml", tmp_path / "good.yaml")
    (tmp_path / "broken.yaml").write_text("metadata: {id: nope}\n", encoding="utf-8")

    catalog = ScenarioCatalog.from_dir(tmp_path)
    assert catalog.ids() == ["AGT-XPIA-001"]
    assert len(catalog.load_errors) == 1


def test_catalog_select_filters_by_profile() -> None:
    catalog = ScenarioCatalog.from_dir(SCENARIO_DIR)
    pr = {s.id for s in catalog.select(profile="pr")}
    nightly = {s.id for s in catalog.select(profile="nightly")}
    # MEMPOIS is nightly-only by design; it is slow and multi-session.
    assert "AGT-MEMPOIS-001" in nightly
    assert "AGT-MEMPOIS-001" not in pr


def test_tested_axes_reflects_the_contract() -> None:
    catalog = ScenarioCatalog.from_dir(SCENARIO_DIR)
    assert catalog.get("AGT-XPIA-001").tested_axes == [
        "prevention", "detection", "evidence"
    ]
    assert catalog.get("AGT-TENANT-001").tested_axes == [
        "prevention", "detection", "evidence", "response"
    ]


def test_output_assertion_without_value_is_an_error() -> None:
    """Caught at authoring time, not just at evaluation time."""
    doc = _minimal()
    doc["spec"]["contract"]["prevention"]["must_not"] = [{"kind": "output_contains"}]
    report = validate_scenario(Scenario.model_validate(doc))
    assert any(i.code == "output_assertion_without_value" for i in report.errors)


def test_invalid_regex_is_an_authoring_error() -> None:
    doc = _minimal()
    doc["spec"]["contract"]["prevention"]["must_not"] = [
        {"kind": "output_matches", "value": "([unclosed"}
    ]
    report = validate_scenario(Scenario.model_validate(doc))
    assert any(i.code == "invalid_regex" for i in report.errors)


def test_unscoped_tool_assertion_warns() -> None:
    doc = _minimal()
    doc["spec"]["contract"]["prevention"]["must_not"] = [{"kind": "tool_call"}]
    report = validate_scenario(Scenario.model_validate(doc))
    assert "unscoped_tool_assertion" in [i.code for i in report.warnings]


def test_egress_assertion_without_resource_is_an_error() -> None:
    doc = _minimal()
    doc["spec"]["contract"]["prevention"]["must_not"] = [{"kind": "http_egress"}]
    report = validate_scenario(Scenario.model_validate(doc))
    assert any(i.code == "egress_without_resource" for i in report.errors)
