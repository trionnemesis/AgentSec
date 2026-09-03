"""Posture coverage: does anything prove what a static finding claims?

AgentShield (or any SARIF-emitting scanner) can flag a surface as risky.
``not_tested`` is the default here for exactly the reason it is the default
for an axis a contract never asserted on (#20, ADR 0002): a surface that was
*scanned* has not thereby been *tested*. A finding is ``covered`` only once
**one scenario** satisfies all three parts of the contract:

    path_match(finding.file, scenario config-surface tags)
    AND threat_semantic_match(finding.category, scenario threat-class tags)
    AND scenario_id in scenarios_with_a_verdict

Everything else on a known surface is ``not_tested``; an unknown surface is
``n/a``. Path and threat both matching is not enough on its own either —
existing in the catalogue is not "coverage" any more than a scenario nobody
has run yet is, the same reason a scenario declaring a ``config-surface:`` but
no ``threat-class:`` never covers a finding: it has not said which threat it
settles, so there is nothing to check the finding's category against.

Both correlations reuse the existing ``metadata.tags`` extensibility point —
the scenario schema is ``extra="forbid"`` and has no dedicated field for
either — with one convention each:

    tags:
      - config-surface:.claude/hooks/guard_agentsec.py
      - threat-class:injection

A ``config-surface:`` tag naming a directory covers every file under it.
``threat-class:<value>`` matches a finding whose scanner-emitted ``category``
equals ``<value>``, compared lowercased and whitespace-stripped. Why category
and not the scanner's own rule id, why no AgentSec-maintained rule -> threat
table, and why a ``threat-class:`` tag must never be given the value
``uncategorised`` are all answered in ``scenario/surface_tags.py``, which owns
both tag conventions.

The risk plane (``inspect/triage.py``) asks its own version of the surface
question but stops at the path match: a :class:`~agentsec.models.risk.RepoRisk`
comes from this repository's own deterministic rules, not a scanner report, so
it carries no scanner-emitted category for a threat-class tag to match against
— the threat requirement is not merely deferred there, it is not yet
expressible. That is a deliberate asymmetry between the two planes, not an
oversight: extending ``scenarios_covering`` itself would grow a parameter the
risk plane has no value to pass, which is why the threat match is a separate,
additional predicate the posture plane alone applies.

This is also the convention the ``AGT-CONFIG-*`` family (#26) is written to
use, but nothing here depends on that family existing — an uncorrelated
finding simply stays ``not_tested``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from agentsec.errors import UnsafePath
from agentsec.models.posture import CoverageState, StaticPostureFinding
from agentsec.project.discovery import Discovery
from agentsec.project.resolver import safe_child
from agentsec.scenario.catalog import ScenarioCatalog
from agentsec.scenario.surface_tags import (
    CONFIG_SURFACE_TAG_PREFIX,
    scenario_surface_tags,
    scenario_threat_classes,
    scenarios_matching_threat,
)
from agentsec.scenario.surface_tags import under as _under

__all__ = [
    "CONFIG_SURFACE_TAG_PREFIX",
    "FindingCoverage",
    "compute_posture_coverage",
    "coverage_counts",
]


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
    return {surface.path for surface in discovery.all_surfaces()}


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
    scenario_tags = scenario_surface_tags(catalog)
    threat_tags = scenario_threat_classes(catalog)

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

        matched = scenarios_matching_threat(
            finding.file, finding.category, scenario_tags, threat_tags
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
