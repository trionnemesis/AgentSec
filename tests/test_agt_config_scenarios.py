"""AGT-CONFIG-* (#26): the agent-configuration attack channel.

The acceptance matrix from the issue, pinned down directly:

* `agentsec validate --strict` on each new scenario -> 0 errors, 0 warnings.
* `agentsec validate-detection` against `demo-agent-fixture` -> checkable.
* The family does not intrude on the bundled corpus: `demo-agent-fixture`'s
  nightly selection is exactly the four original scenarios, unchanged
  (`test_pipeline.py::test_full_run_produces_the_expected_verdict_matrix` is
  the reference; this file additionally asserts the catalogue grew to 8
  without moving that selection).
* Coverage report: the OWASP category count rises, and still-uncovered
  categories are named.
* A `must_fire` with no `rule_id` fails a `--strict` gate (`agentsec validate
  --strict` treats a warning as a failure; the rule itself, `unspecific_alert_
  assertion`, is issue #10's, and is not modified here).

`hooks/guard_agentsec.py` is the fixture corpus's operator: these scenarios
validate clean and are checkable, but do not carry recorded fixtures and are
scoped away from `demo-agent-fixture` (see each scenario's `target.environments`).
"""

from __future__ import annotations

import copy

import pytest
import yaml

from agentsec.scenario.catalog import ScenarioCatalog
from agentsec.scenario.loader import load_scenario_file
from agentsec.scenario.validator import validate_scenario, validate_scenario_dict
from agentsec.service.harness import HarnessService
from tests.conftest import REPO_ROOT

SCENARIO_DIR = REPO_ROOT / "scenarios"
CONFIG_SCENARIO_IDS = [
    "AGT-CONFIG-001", "AGT-CONFIG-002", "AGT-CONFIG-003", "AGT-CONFIG-004",
]


@pytest.mark.parametrize("scenario_id", CONFIG_SCENARIO_IDS)
def test_strict_validation_is_clean(scenario_id: str) -> None:
    path = SCENARIO_DIR / f"{scenario_id}.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    schema_report = validate_scenario_dict(raw)
    assert schema_report.ok, [i.render() for i in schema_report.errors]

    scenario = load_scenario_file(path)
    report = validate_scenario(scenario, raw=raw)
    assert not report.errors, [i.render() for i in report.errors]
    assert not report.warnings, [i.render() for i in report.warnings]
    assert "red_only" not in {i.code for i in report.issues}


@pytest.mark.parametrize("scenario_id", CONFIG_SCENARIO_IDS)
def test_every_must_fire_names_a_rule(scenario_id: str) -> None:
    """Non-negotiable #2: a rule_id, not only a level."""
    scenario = load_scenario_file(SCENARIO_DIR / f"{scenario_id}.yaml")
    wazuh = scenario.spec.contract.detection.wazuh
    assert wazuh is not None and wazuh.must_fire
    assert all(a.rule_id for a in wazuh.must_fire)


@pytest.mark.parametrize("scenario_id", CONFIG_SCENARIO_IDS)
def test_response_axis_is_honestly_not_tested(scenario_id: str) -> None:
    """Non-negotiable #1: no runbook or automation exists yet for this family."""
    scenario = load_scenario_file(SCENARIO_DIR / f"{scenario_id}.yaml")
    assert scenario.spec.contract.response.mode == "not_tested"


@pytest.mark.parametrize("scenario_id", CONFIG_SCENARIO_IDS)
def test_new_scenarios_land_non_blocking(scenario_id: str) -> None:
    """Non-negotiable #4: new scenarios land non-blocking."""
    scenario = load_scenario_file(SCENARIO_DIR / f"{scenario_id}.yaml")
    assert scenario.spec.regression.gate == "warning"


@pytest.mark.parametrize("scenario_id", CONFIG_SCENARIO_IDS)
def test_validate_detection_against_demo_agent_fixture_is_checkable(
    scenario_id: str, service: HarnessService
) -> None:
    result = service.validate_detection(scenario_id=scenario_id, target_id="demo-agent-fixture")
    assert result["checkable"] is True, result["issues"]
    assert result["expected_wazuh_rules"], "must_fire without a rule_id would leave this empty"


def test_the_family_does_not_intrude_on_the_bundled_corpus_selection(
    service: HarnessService,
) -> None:
    """The catalogue grows; demo-agent-fixture's nightly selection does not."""
    assert len(service.catalog) == 8
    result = service.start_run(target_id="demo-agent-fixture", profile="nightly")
    assert {r.scenario_id for r in result.runs} == {
        "AGT-XPIA-001", "AGT-TOOLLOOP-001", "AGT-TENANT-001", "AGT-MEMPOIS-001",
    }


def test_coverage_report_rises_and_names_what_remains_uncovered(
    service: HarnessService,
) -> None:
    coverage = service.catalog.coverage()
    assert coverage["covered_categories"] == 8
    assert coverage["coverage_ratio"] == pytest.approx(0.8)
    uncovered = {c["id"] for c in coverage["categories"] if not c["covered"]}
    assert uncovered == {"AAI005", "AAI010"}


def test_a_must_fire_without_a_rule_id_fails_a_strict_gate() -> None:
    """Acceptance-matrix row: 'validator error'. The existing rule this exercises
    (`unspecific_alert_assertion`, issue #10) is a warning, not a schema/logic
    error — but `agentsec validate --strict` (the CI gate) treats any warning as
    a failure, which is the property this test pins down rather than changing
    the rule's severity for every other scenario in the repository."""
    path = SCENARIO_DIR / "AGT-CONFIG-003.yaml"
    doc = copy.deepcopy(yaml.safe_load(path.read_text(encoding="utf-8")))
    del doc["spec"]["contract"]["detection"]["wazuh"]["must_fire"][0]["rule_id"]

    from agentsec.models.scenario import Scenario

    scenario = Scenario.model_validate(doc)
    report = validate_scenario(scenario, raw=doc)
    assert report.ok  # still no schema/logic error
    codes = {i.code for i in report.warnings}
    assert "unspecific_alert_assertion" in codes

    strict_would_fail = bool(report.errors) or bool(report.warnings)
    assert strict_would_fail


def test_config_surface_tags_follow_the_convention_posture_coverage_reads() -> None:
    """#25's coverage correlation reads `config-surface:<path>` tags; confirm
    every new scenario actually carries one, or a future posture report can
    never mark its surface `covered`."""
    catalog = ScenarioCatalog.from_dir(SCENARIO_DIR)
    for scenario_id in CONFIG_SCENARIO_IDS:
        tags = catalog.get(scenario_id).metadata.tags
        assert any(t.startswith("config-surface:") for t in tags), scenario_id


def test_config_scenarios_also_declare_the_threat_class_they_settle() -> None:
    """#68's threat-semantic coverage additionally reads `threat-class:<value>`
    tags; confirm every `AGT-CONFIG-*` carries at least one with a non-empty,
    lowercase value, or it can never cover a posture finding no matter how
    well its `config-surface:` tag matches. Deliberately does not pin which
    values are used — that vocabulary belongs to the upstream scanner, not to
    this test."""
    catalog = ScenarioCatalog.from_dir(SCENARIO_DIR)
    for scenario_id in CONFIG_SCENARIO_IDS:
        tags = catalog.get(scenario_id).metadata.tags
        threat_values = [
            tag[len("threat-class:"):] for tag in tags if tag.startswith("threat-class:")
        ]
        assert threat_values, scenario_id
        assert all(v.strip() and v == v.lower() for v in threat_values), scenario_id
