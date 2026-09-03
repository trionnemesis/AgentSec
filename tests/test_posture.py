"""Static posture ingestion (#25): a scanner grade is input, never a verdict.

Covers the issue's acceptance matrix: the adapter (AgentShield JSON + SARIF,
unknown shape -> error), coverage correlation (covered/not_tested/n/a,
not_tested as the honest default), the path-escape refusal, and the
end-to-end harness wiring (no report -> not_tested; ingested report with zero
purple scenarios leaves `purple` untouched and the plane is never a verdict).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.errors import PostureIngestionError, UnsafePath
from agentsec.models.posture import StaticPostureFinding
from agentsec.models.scenario import (
    Attack,
    AttackStep,
    Contract,
    Risk,
    Scenario,
    ScenarioMetadata,
    ScenarioSpec,
    TargetSelector,
)
from agentsec.posture.adapter import load_posture_report, resolve_report_path
from agentsec.posture.coverage import compute_posture_coverage, coverage_counts
from agentsec.project.discovery import Discovery, Surface
from agentsec.scenario.catalog import CatalogEntry, ScenarioCatalog
from agentsec.service.harness import HarnessService

# -- adapter -------------------------------------------------------------


def _write(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_agentshield_json_is_normalised(tmp_path: Path) -> None:
    report = {
        "score": {"grade": "C", "numericScore": 66, "breakdown": {}},
        "findings": [
            {
                "id": "hook-shell-interp", "severity": "high", "category": "hooks",
                "title": "Hook interpolates untrusted content",
                "file": ".claude/hooks/guard.py", "runtimeConfidence": "active-runtime",
            }
        ],
    }
    parsed = load_posture_report(_write(tmp_path / "r.json", report))
    assert parsed.source_tool == "agentshield"
    assert len(parsed.findings) == 1
    finding = parsed.findings[0]
    assert finding.rule_id == "hook-shell-interp"
    assert finding.severity == "high"
    assert finding.file == ".claude/hooks/guard.py"
    # The matched snippet, if AgentShield's own report had quoted one, is not
    # even a field on StaticPostureFinding — there is nothing to redact later.
    assert not hasattr(finding, "matched_text")


def test_sarif_is_normalised_and_severity_is_mapped(tmp_path: Path) -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "AgentShield", "version": "1.4.0", "rules": [
                    {"id": "mcp-risky-fs", "shortDescription": {"text": "Broad FS access"}}
                ]}},
                "results": [
                    {
                        "ruleId": "mcp-risky-fs", "level": "error",
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": ".mcp.json"}}}
                        ],
                    }
                ],
            }
        ],
    }
    parsed = load_posture_report(_write(tmp_path / "r.sarif.json", sarif))
    assert parsed.source_tool == "agentshield"
    assert parsed.source_version == "1.4.0"
    assert parsed.findings[0].severity == "high"  # SARIF 'error' -> our 'high'
    assert parsed.findings[0].title == "Broad FS access"


def _sarif_result(rule_id: str, file_path: str) -> dict:
    return {
        "ruleId": rule_id, "level": "warning",
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": file_path}}}],
    }


def test_two_scanners_same_rule_id_are_both_kept_and_distinguished() -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "toolA", "rules": []}},
                "results": [_sarif_result("shared-rule", "a.py")],
            },
            {
                "tool": {"driver": {"name": "toolB", "rules": []}},
                "results": [_sarif_result("shared-rule", "a.py")],
            },
        ],
    }
    from agentsec.posture.adapter import _from_sarif  # noqa: SLF001 - direct unit test

    parsed = _from_sarif(sarif)
    assert len(parsed.findings) == 2
    assert {f.source_tool for f in parsed.findings} == {"toola", "toolb"}
    assert all(f.rule_id == "shared-rule" for f in parsed.findings)


def test_an_unrecognised_shape_is_an_error_not_an_empty_pass(tmp_path: Path) -> None:
    path = _write(tmp_path / "r.json", {"unrelated": True, "version": "9.9.9"})
    with pytest.raises(PostureIngestionError) as exc_info:
        load_posture_report(path)
    assert exc_info.value.details.get("version") == "9.9.9"


def test_an_unrecognised_severity_is_an_error() -> None:
    report = {
        "score": {"grade": "A"},
        "findings": [
            {"id": "x", "severity": "catastrophic", "category": "c", "file": "f", "title": "t"}
        ],
    }
    with pytest.raises(PostureIngestionError, match="severity"):
        from agentsec.posture.adapter import _from_agentshield  # noqa: SLF001

        _from_agentshield(report)


def test_resolve_report_path_refuses_a_traversal(tmp_path: Path) -> None:
    with pytest.raises(UnsafePath):
        resolve_report_path(tmp_path, "../outside.json")


# -- coverage --------------------------------------------------------------


def _finding(
    rule_id: str, file: str, severity: str = "high", category: str = "hooks"
) -> StaticPostureFinding:
    return StaticPostureFinding(
        rule_id=rule_id, severity=severity, category=category, file=file,
        title=rule_id, source_tool="agentshield",
    )


def _discovery(*, hook_path: str = ".claude/hooks/guard.py") -> Discovery:
    return Discovery(
        project_id="demo", name="Demo", description="",
        hooks=[Surface(id="guard", kind="hook", path=hook_path)],
    )


def _scenario(scenario_id: str, tags: list[str]) -> Scenario:
    return Scenario(
        metadata=ScenarioMetadata(
            id=scenario_id, title="A tagged test scenario", severity="low", tags=tags
        ),
        spec=ScenarioSpec(
            target=TargetSelector(environments=["local"]),
            risk=Risk(level="low"),
            attack=Attack(executor="replay", steps=[AttackStep(id="s1", kind="wait")]),
            contract=Contract(),
        ),
    )


def test_a_finding_on_an_unknown_surface_is_not_applicable(tmp_path: Path) -> None:
    rows, problems = compute_posture_coverage(
        [_finding("r1", "README.md")],
        root=tmp_path, discovery=_discovery(), catalog=ScenarioCatalog([]),
        scenarios_with_a_verdict=set(),
    )
    assert rows[0].state == "n/a"
    assert problems == []


def test_a_known_surface_with_no_tagged_scenario_is_not_tested(tmp_path: Path) -> None:
    rows, _ = compute_posture_coverage(
        [_finding("r1", ".claude/hooks/guard.py")],
        root=tmp_path, discovery=_discovery(), catalog=ScenarioCatalog([]),
        scenarios_with_a_verdict=set(),
    )
    assert rows[0].state == "not_tested"


def test_a_tagged_scenario_that_never_ran_is_still_not_tested(tmp_path: Path) -> None:
    """Existing in the catalogue is not coverage — something has to have run."""
    scenario = _scenario(
        "AGT-CONFIG-900", ["config-surface:.claude/hooks/guard.py", "threat-class:hooks"]
    )
    catalog = ScenarioCatalog([CatalogEntry(scenario, Path("x.yaml"))])
    rows, _ = compute_posture_coverage(
        [_finding("r1", ".claude/hooks/guard.py")],
        root=tmp_path, discovery=_discovery(), catalog=catalog,
        scenarios_with_a_verdict=set(),  # nothing has actually run
    )
    assert rows[0].state == "not_tested"
    assert rows[0].scenario_ids == ["AGT-CONFIG-900"]


def test_a_tagged_scenario_with_a_verdict_makes_the_finding_covered(tmp_path: Path) -> None:
    scenario = _scenario(
        "AGT-CONFIG-900", ["config-surface:.claude/hooks/guard.py", "threat-class:hooks"]
    )
    catalog = ScenarioCatalog([CatalogEntry(scenario, Path("x.yaml"))])
    rows, _ = compute_posture_coverage(
        [_finding("r1", ".claude/hooks/guard.py")],
        root=tmp_path, discovery=_discovery(), catalog=catalog,
        scenarios_with_a_verdict={"AGT-CONFIG-900"},
    )
    assert rows[0].state == "covered"
    assert rows[0].scenario_ids == ["AGT-CONFIG-900"]


def test_a_directory_tag_covers_every_file_under_it(tmp_path: Path) -> None:
    scenario = _scenario(
        "AGT-CONFIG-901", ["config-surface:.claude/hooks", "threat-class:hooks"]
    )
    catalog = ScenarioCatalog([CatalogEntry(scenario, Path("x.yaml"))])
    rows, _ = compute_posture_coverage(
        [_finding("r1", ".claude/hooks/guard.py")],
        root=tmp_path, discovery=_discovery(), catalog=catalog,
        scenarios_with_a_verdict={"AGT-CONFIG-901"},
    )
    assert rows[0].state == "covered"


def test_a_finding_outside_the_project_root_is_a_problem_not_n_a(tmp_path: Path) -> None:
    rows, problems = compute_posture_coverage(
        [_finding("r1", "../../etc/passwd")],
        root=tmp_path, discovery=_discovery(), catalog=ScenarioCatalog([]),
        scenarios_with_a_verdict=set(),
    )
    assert rows == []
    assert problems[0]["rule_id"] == "r1"
    assert "escapes the project" in problems[0]["detail"]


def test_coverage_counts_tally_all_three_states(tmp_path: Path) -> None:
    scenario = _scenario(
        "AGT-CONFIG-900", ["config-surface:.claude/hooks/guard.py", "threat-class:hooks"]
    )
    catalog = ScenarioCatalog([CatalogEntry(scenario, Path("x.yaml"))])
    rows, _ = compute_posture_coverage(
        [_finding("r1", ".claude/hooks/guard.py"), _finding("r2", "README.md")],
        root=tmp_path, discovery=_discovery(), catalog=catalog,
        scenarios_with_a_verdict={"AGT-CONFIG-900"},
    )
    assert coverage_counts(rows) == {"covered": 1, "not_tested": 0, "n/a": 1}


def test_same_file_different_threat_is_not_covered(tmp_path: Path) -> None:
    """Path alone must not decide `covered`: two findings on the same file but
    a different threat category must not both ride the one scenario's verdict
    — only the one whose `threat-class:` tag actually matches the finding's
    category may. Reproduces the Stage 0 defect (issue #68)."""
    scenario = _scenario(
        "AGT-CONFIG-902", ["config-surface:.claude/hooks", "threat-class:injection"]
    )
    catalog = ScenarioCatalog([CatalogEntry(scenario, Path("x.yaml"))])
    rows, _ = compute_posture_coverage(
        [
            _finding("r-inj", ".claude/hooks/guard.py", category="injection"),
            _finding("r-exp", ".claude/hooks/guard.py", category="exposure"),
        ],
        root=tmp_path, discovery=_discovery(), catalog=catalog,
        scenarios_with_a_verdict={"AGT-CONFIG-902"},
    )
    by_rule = {r.finding.rule_id: r for r in rows}
    assert by_rule["r-inj"].state == "covered"
    assert by_rule["r-inj"].scenario_ids == ["AGT-CONFIG-902"]
    assert by_rule["r-exp"].state == "not_tested"
    assert by_rule["r-exp"].scenario_ids == []


def test_a_surface_tag_without_a_threat_class_never_covers(tmp_path: Path) -> None:
    """A scenario that names a surface but never says which threat it settles
    must not cover a finding there, verdict or not — an unstated threat is not
    an implicit match against anything a scanner might report."""
    scenario = _scenario("AGT-CONFIG-903", ["config-surface:.claude/hooks/guard.py"])
    catalog = ScenarioCatalog([CatalogEntry(scenario, Path("x.yaml"))])
    rows, _ = compute_posture_coverage(
        [_finding("r1", ".claude/hooks/guard.py", category="injection")],
        root=tmp_path, discovery=_discovery(), catalog=catalog,
        scenarios_with_a_verdict={"AGT-CONFIG-903"},
    )
    assert rows[0].state == "not_tested"
    assert rows[0].scenario_ids == []


def test_a_threat_class_without_a_surface_match_never_covers(tmp_path: Path) -> None:
    """The threat tag alone is not enough either — the scenario has to name
    the finding's actual file, not merely settle the right kind of threat
    somewhere else in the repository."""
    scenario = _scenario(
        "AGT-CONFIG-904", ["config-surface:.mcp.json", "threat-class:hooks"]
    )
    catalog = ScenarioCatalog([CatalogEntry(scenario, Path("x.yaml"))])
    rows, _ = compute_posture_coverage(
        [_finding("r1", ".claude/hooks/guard.py", category="hooks")],
        root=tmp_path, discovery=_discovery(), catalog=catalog,
        scenarios_with_a_verdict={"AGT-CONFIG-904"},
    )
    assert rows[0].state == "not_tested"
    assert rows[0].scenario_ids == []


def test_not_tested_lists_only_scenarios_that_would_settle_the_threat(tmp_path: Path) -> None:
    """`not_tested.scenario_ids` must not surface a scenario whose tags could
    never have covered this finding even if it had run — only a scenario that
    also matches the threat belongs on that list."""
    settles_the_threat = _scenario(
        "AGT-CONFIG-905", ["config-surface:.claude/hooks/guard.py", "threat-class:injection"]
    )
    surface_only = _scenario("AGT-CONFIG-906", ["config-surface:.claude/hooks/guard.py"])
    catalog = ScenarioCatalog(
        [
            CatalogEntry(settles_the_threat, Path("a.yaml")),
            CatalogEntry(surface_only, Path("b.yaml")),
        ]
    )
    rows, _ = compute_posture_coverage(
        [_finding("r1", ".claude/hooks/guard.py", category="injection")],
        root=tmp_path, discovery=_discovery(), catalog=catalog,
        scenarios_with_a_verdict=set(),  # neither has actually run
    )
    assert rows[0].state == "not_tested"
    assert rows[0].scenario_ids == ["AGT-CONFIG-905"]


def test_threat_class_match_ignores_case_and_whitespace(tmp_path: Path) -> None:
    scenario = _scenario(
        "AGT-CONFIG-907", ["config-surface:.claude/hooks/guard.py", "threat-class: Hooks "]
    )
    catalog = ScenarioCatalog([CatalogEntry(scenario, Path("x.yaml"))])
    rows, _ = compute_posture_coverage(
        [_finding("r1", ".claude/hooks/guard.py", category=" HOOKS ")],
        root=tmp_path, discovery=_discovery(), catalog=catalog,
        scenarios_with_a_verdict={"AGT-CONFIG-907"},
    )
    assert rows[0].state == "covered"
    assert rows[0].scenario_ids == ["AGT-CONFIG-907"]


# -- harness end-to-end ------------------------------------------------------


def test_no_report_configured_is_not_tested_never_green(service: HarnessService) -> None:
    """`service`'s workspace has no .agentsec manifest at all — the same absence
    a real repository that never ran `agentsec init` would have."""
    doc = service.dashboard()
    assert doc["static_posture"]["status"] == "not_tested"
    assert doc["static_posture"]["reason"] == "project_not_initialised"


def test_ingested_report_never_moves_purple_or_the_project_plane(
    service: HarnessService, workspace: Path
) -> None:
    """Acceptance-matrix row: grade A, zero purple scenarios asserting on the
    flagged surface -> posture plane green, purple unchanged, never `secure`
    by virtue of the scan."""
    (workspace / ".agentsec").mkdir()
    (workspace / ".agentsec" / "project.yaml").write_text(
        "apiVersion: agentsec.dev/v1alpha1\nkind: Project\n"
        "project_id: demo-project\nname: Demo\n"
        "static_posture_report: posture-report.json\n"
    )
    (workspace / ".claude" / "hooks").mkdir(parents=True)
    (workspace / ".claude" / "hooks" / "guard.py").write_text("print('hi')\n")
    report = {
        "score": {"grade": "A", "numericScore": 100, "breakdown": {}},
        "findings": [
            {"id": "hook-x", "severity": "high", "category": "hooks",
             "title": "Untested hook risk", "file": ".claude/hooks/guard.py"}
        ],
    }
    (workspace / "posture-report.json").write_text(json.dumps(report))

    baseline = service.dashboard()["purple"]

    fresh = HarnessService(service.settings, actor="pytest")
    doc = fresh.dashboard()

    assert doc["static_posture"]["status"] == "ingested"
    assert doc["static_posture"]["counts"]["not_tested"] == 1
    # purple is exactly what it was before any report existed: ingestion
    # changed nothing about the four-axis rollup.
    assert {k: v for k, v in doc["purple"].items() if k != "generated_at"} == {
        k: v for k, v in baseline.items() if k != "generated_at"
    }


def test_an_unparseable_report_is_an_error_not_not_tested(
    service: HarnessService, workspace: Path
) -> None:
    (workspace / ".agentsec").mkdir()
    (workspace / ".agentsec" / "project.yaml").write_text(
        "apiVersion: agentsec.dev/v1alpha1\nkind: Project\n"
        "project_id: demo-project\nname: Demo\n"
        "static_posture_report: posture-report.json\n"
    )
    (workspace / "posture-report.json").write_text(json.dumps({"nonsense": True}))

    fresh = HarnessService(service.settings, actor="pytest")
    doc = fresh.dashboard()
    assert doc["static_posture"]["status"] == "error"
    assert doc["static_posture"]["reason"] == "unrecognised_schema"


def test_the_published_dashboard_never_carries_the_matched_snippet(
    service: HarnessService, workspace: Path
) -> None:
    """Even if a scanner's title happened to quote something secret-shaped, the
    publisher only projects rule_id/severity/category/file/title/coverage —
    nothing here is capable of carrying an arbitrary extra field through."""
    from agentsec.reporting.publish import publish

    (workspace / ".agentsec").mkdir()
    (workspace / ".agentsec" / "project.yaml").write_text(
        "apiVersion: agentsec.dev/v1alpha1\nkind: Project\n"
        "project_id: demo-project\nname: Demo\n"
        "static_posture_report: posture-report.json\n"
    )
    report = {
        "score": {"grade": "A"},
        "findings": [
            {"id": "secret-x", "severity": "critical", "category": "secrets",
             "title": "hardcoded key detected", "file": "config.py"}
        ],
    }
    (workspace / "posture-report.json").write_text(json.dumps(report))

    fresh = HarnessService(service.settings, actor="pytest")
    published = publish("dashboard", fresh.dashboard())
    finding = published["static_posture"]["findings"][0]
    assert set(finding) == {
        "rule_id", "severity", "category", "file", "title", "source_tool",
        "coverage", "scenario_ids",
    }
