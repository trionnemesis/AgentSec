"""The handoff: which static risks can become deterministic conclusions.

This is the seam the whole product path turns on. A rule in ``rules.py`` says
"this looks wrong". The Purple Harness says "this *is* wrong, and here is
whether anything noticed". Triage decides which risks can cross that gap, and —
more importantly — states plainly which cannot.

The matching reuses the ``config-surface:`` tag convention rather than inventing
a second one, so a scenario written to cover a surface for the static posture
plane covers it here too, and one that is retagged moves both at once. See
``scenario/surface_tags.py``.

Three states, and the default is the pessimistic one:

* ``verified`` — a scenario declaring this surface has produced a verdict. The
  answer is in the ``purple`` plane; this plane only points at it.
* ``verifiable`` — such a scenario exists but has not run here. This is the
  queue ``agentsec scan --verify`` drains.
* ``not_verifiable`` — nothing in the catalogue exercises this surface, so the
  static rule is the only thing anyone has. Most risks are here today.

``not_verifiable`` is deliberately not a failure and equally deliberately not a
pass. It is the honest report that AgentSec found something it cannot settle,
and rendering it as either would be the failure this project exists to prevent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentsec.models.risk import (
    RepoRisk,
    Verification,
    severity_counts,
    sort_key,
    verification_counts,
)
from agentsec.scenario.catalog import ScenarioCatalog
from agentsec.scenario.surface_tags import scenario_surface_tags, scenarios_covering

RISK_SCHEMA_VERSION = "1.0.0"


def triage(
    risks: list[RepoRisk],
    *,
    catalog: ScenarioCatalog,
    scenarios_with_a_verdict: set[str],
) -> list[RepoRisk]:
    """Attach a :class:`Verification` to every risk, worst first."""
    surface_tags = scenario_surface_tags(catalog)
    out: list[RepoRisk] = []
    for risk in risks:
        matched = scenarios_covering(risk.file, surface_tags)
        out.append(risk.model_copy(update={"verification": _verify(matched,
                                                                   scenarios_with_a_verdict)}))
    return sorted(out, key=sort_key)


def _verify(matched: list[str], scenarios_with_a_verdict: set[str]) -> Verification:
    if not matched:
        return Verification(
            state="not_verifiable",
            detail=(
                "no scenario declares this configuration surface, so nothing here "
                "can turn the static match into a verdict"
            ),
        )
    ran = [sid for sid in matched if sid in scenarios_with_a_verdict]
    if ran:
        return Verification(
            state="verified",
            scenario_ids=ran,
            detail="a scenario covering this surface has produced a verdict; see the purple plane",
        )
    return Verification(
        state="verifiable",
        scenario_ids=matched,
        detail="a scenario covers this surface but has not run here yet",
    )


@dataclass
class RiskReport:
    """The repository risk plane, as one document.

    ``status`` mirrors the other planes' vocabulary rather than inventing its
    own: a caller that cannot distinguish "inspected and clean" from "never
    inspected" will eventually render the second as the first.
    """

    project_id: str
    risks: list[RepoRisk] = field(default_factory=list)
    problems: list[dict[str, str]] = field(default_factory=list)

    @property
    def verify_queue(self) -> list[str]:
        """Scenario ids that would settle a high or critical risk, and have not run.

        This is the list ``agentsec scan --verify`` hands to the harness. Sorted
        and de-duplicated: one scenario often covers several risks on the same
        surface, and running it once settles all of them.
        """
        queue: set[str] = set()
        for risk in self.risks:
            if risk.should_verify:
                queue.update(risk.verification.scenario_ids)
        return sorted(queue)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "inspected",
            "schema_version": RISK_SCHEMA_VERSION,
            "project_id": self.project_id,
            "counts": {
                "total": len(self.risks),
                "by_severity": severity_counts(self.risks),
                "by_verification": verification_counts(self.risks),
            },
            "verify_queue": self.verify_queue,
            "risks": [risk.to_dict() for risk in self.risks],
            "problems": self.problems,
        }
