"""Posture coverage: does anything prove what a static finding claims?

AgentShield (or any SARIF-emitting scanner) can flag a surface as risky.
``not_tested`` is the default here for exactly the reason it is the default
for an axis a contract never asserted on (#20, ADR 0002): a surface that was
*scanned* has not thereby been *tested*. A finding is ``covered`` only once a
scenario that exercises its file has actually produced a verdict — existing
in the catalogue is not enough, the same way a scenario nobody has run yet is
not "coverage" of anything.

Correlation needs a scenario to say which configuration surface it exercises,
and the scenario schema (``extra="forbid"``) has no dedicated field for that.
Rather than widen the contract, this reuses the existing ``metadata.tags``
extensibility point with one convention:

    tags: ["config-surface:.claude/hooks/guard_agentsec.py"]

A tag naming a directory (``config-surface:.claude/hooks``) covers every file
under it. This is also the convention the ``AGT-CONFIG-*`` family (#26) is
written to use, but nothing here depends on that family existing — an
uncorrelated finding simply stays ``not_tested``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from agentsec.errors import UnsafePath
from agentsec.models.posture import CoverageState, StaticPostureFinding
from agentsec.project.discovery import Discovery
from agentsec.project.resolver import safe_child
from agentsec.scenario.catalog import ScenarioCatalog

CONFIG_SURFACE_TAG_PREFIX = "config-surface:"


@dataclass
class FindingCoverage:
    finding: StaticPostureFinding
    state: CoverageState
    scenario_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.finding.rule_id,
            "severity": self.finding.severity,
            "category": self.finding.category,
            "file": self.finding.file,
            "title": self.finding.title,
            "source_tool": self.finding.source_tool,
            "coverage": self.state,
            "scenario_ids": self.scenario_ids,
        }


def _known_surface_paths(discovery: Discovery) -> set[str]:
    paths: set[str] = set()
    for group in (discovery.skills, discovery.agents, discovery.hooks, discovery.mcp_servers):
        paths.update(s.path for s in group)
    for single in (discovery.settings, discovery.instructions):
        if single is not None:
            paths.add(single.path)
    return paths


def _under(file_path: str, surface_path: str) -> bool:
    """True if ``file_path`` is ``surface_path`` or lives under it as a directory."""
    return file_path == surface_path or file_path.startswith(surface_path.rstrip("/") + "/")


def _scenario_surface_tags(catalog: ScenarioCatalog) -> dict[str, list[str]]:
    """scenario_id -> the config-surface paths/prefixes its tags declare."""
    out: dict[str, list[str]] = {}
    for entry in catalog:
        surfaces = [
            t[len(CONFIG_SURFACE_TAG_PREFIX):]
            for t in entry.scenario.metadata.tags
            if t.startswith(CONFIG_SURFACE_TAG_PREFIX)
        ]
        if surfaces:
            out[entry.id] = surfaces
    return out


def compute_posture_coverage(
    findings: list[StaticPostureFinding],
    *,
    root: Path,
    discovery: Discovery,
    catalog: ScenarioCatalog,
    scenarios_with_a_verdict: set[str],
) -> tuple[list[FindingCoverage], list[dict[str, str]]]:
    """Per-finding coverage state, and the findings refused outright.

    ``scenarios_with_a_verdict`` is the set of scenario ids that have actually
    produced a run — typically ``{s.scenario_id for s in latest_per_scenario(...)}``.
    A scenario merely existing in the catalogue, tagged at the right surface but
    never run, leaves its findings ``not_tested``: nothing has proven anything yet.

    A finding whose ``file`` resolves outside ``root`` is not correlated at
    all — a scanner is not more trustworthy than a project manifest, so it
    gets the same refusal any other declared location would (``safe_child``),
    recorded as a problem rather than silently marked ``n/a``.
    """
    known_surfaces = _known_surface_paths(discovery)
    scenario_tags = _scenario_surface_tags(catalog)

    results: list[FindingCoverage] = []
    problems: list[dict[str, str]] = []
    for finding in findings:
        try:
            safe_child(root, finding.file, field="finding.file")
        except UnsafePath as exc:
            problems.append(
                {"rule_id": finding.rule_id, "file": finding.file, "detail": exc.message}
            )
            continue

        if not any(_under(finding.file, surface) for surface in known_surfaces):
            results.append(FindingCoverage(finding=finding, state="n/a"))
            continue

        matched = sorted(
            scenario_id
            for scenario_id, surfaces in scenario_tags.items()
            if any(_under(finding.file, surface) for surface in surfaces)
        )
        run_matched = [sid for sid in matched if sid in scenarios_with_a_verdict]
        if run_matched:
            results.append(
                FindingCoverage(finding=finding, state="covered", scenario_ids=run_matched)
            )
        else:
            # Either nothing is tagged for this surface, or something is but has
            # never been run — both are "nothing has proven this", not a pass.
            results.append(
                FindingCoverage(finding=finding, state="not_tested", scenario_ids=matched)
            )
    return results, problems


def coverage_counts(rows: list[FindingCoverage]) -> dict[str, int]:
    return {
        state: sum(1 for r in rows if r.state == state)
        for state in ("covered", "not_tested", "n/a")
    }
