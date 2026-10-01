"""Static contract checks for the repository-owned Wazuh rule pack."""

from __future__ import annotations

from xml.etree import ElementTree

import pytest

from agentsec.errors import EvidenceUnavailable
from agentsec.evidence.wazuh import _run_id_filter, _wazuh_run_id
from agentsec.scenario.catalog import ScenarioCatalog
from tests.conftest import REPO_ROOT

SCENARIO_DIR = REPO_ROOT / "scenarios"
RULE_PACK = REPO_ROOT / "packaging" / "wazuh" / "agentsec-wazuh-rules.xml"


def _pack_levels() -> dict[str, int]:
    root = ElementTree.parse(RULE_PACK).getroot()
    assert root.tag == "group"
    assert "agentsec" in root.attrib.get("name", "").split(",")

    levels: dict[str, int] = {}
    for rule in root.findall("rule"):
        rule_id = rule.attrib["id"]
        assert rule_id not in levels, f"duplicate Wazuh rule id: {rule_id}"
        levels[rule_id] = int(rule.attrib["level"])
        assert rule.findtext("decoded_as") == "json", rule_id
        assert rule.find("field[@name='agentsec.run_id']") is not None, rule_id
        assert rule.findtext("description"), rule_id
    return levels


def _required_levels() -> dict[str, int]:
    required: dict[str, int] = {}
    catalog = ScenarioCatalog.from_dir(SCENARIO_DIR, strict=True)

    for entry in catalog:
        detection = entry.scenario.spec.contract.detection
        if detection is None or detection.wazuh is None:
            continue
        for assertion in detection.wazuh.must_fire:
            assert assertion.rule_id is not None, entry.id
            min_level = assertion.min_level or 0
            required[assertion.rule_id] = max(required.get(assertion.rule_id, 0), min_level)

    return required


def test_every_shipped_must_fire_rule_exists_at_or_above_its_min_level() -> None:
    pack_levels = _pack_levels()
    required_levels = _required_levels()

    missing = sorted(set(required_levels) - set(pack_levels))
    assert not missing, f"Wazuh rule pack is missing scenario rules: {missing}"

    too_low = {
        rule_id: {"pack": pack_levels[rule_id], "required": min_level}
        for rule_id, min_level in required_levels.items()
        if pack_levels[rule_id] < min_level
    }
    assert not too_low, f"Wazuh rule levels are below scenario min_level: {too_low}"


def test_wazuh_correlation_filter_accepts_root_and_json_decoded_paths() -> None:
    assert _run_id_filter("run-123") == {
        "bool": {
            "should": [
                {"term": {"agentsec.run_id": "run-123"}},
                {"term": {"data.agentsec.run_id": "run-123"}},
            ],
            "minimum_should_match": 1,
        }
    }


def test_wazuh_run_id_reads_json_decoded_data_namespace() -> None:
    assert (
        _wazuh_run_id({"data": {"agentsec": {"run_id": "run-123"}}})
        == "run-123"
    )


def test_wazuh_run_id_rejects_conflicting_root_and_decoded_values() -> None:
    with pytest.raises(EvidenceUnavailable, match="conflicting canonical"):
        _wazuh_run_id(
            {
                "agentsec": {"run_id": "run-root"},
                "data": {"agentsec": {"run_id": "run-decoded"}},
            }
        )
