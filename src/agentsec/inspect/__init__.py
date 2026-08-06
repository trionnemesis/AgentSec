"""Repository risk plane: what an engineer's own repository is exposing.

The step the product path was missing. ``project/discovery.py`` answers *what
surfaces exist*, and the Purple Harness answers *did an attack succeed and did
anyone notice*. Between them sat a gap nobody could cross without already
knowing which scenario to run: an engineer who opens a repository has an
inventory and a catalogue, and no reason to connect any row of one to any row of
the other.

This module closes that gap in two moves. ``rules.py`` reads the discovered
surfaces and raises risks deterministically. ``triage.py`` decides which of
those risks a scenario could settle, and hands the high-severity, actually
runnable subset to the harness.

What it is not: a verdict. Nothing here executes, observes, or gives a detection
control the chance to fire. A risk is a reason to run a scenario — which is why
the plane reports ``not_verifiable`` rather than a grade whenever no scenario
covers the surface it found something on.
"""

from agentsec.inspect.rules import MAX_READ_BYTES, RULES, RuleContext, evaluate
from agentsec.inspect.triage import RISK_SCHEMA_VERSION, RiskReport, triage
from agentsec.models.risk import RepoRisk, Verification, VerificationState

__all__ = [
    "MAX_READ_BYTES",
    "RISK_SCHEMA_VERSION",
    "RULES",
    "RepoRisk",
    "RiskReport",
    "RuleContext",
    "Verification",
    "VerificationState",
    "evaluate",
    "inspect_project",
    "triage",
]


def inspect_project(
    *,
    root,  # noqa: ANN001 - Path; annotated in the signature would need an import cycle guard
    discovery,  # noqa: ANN001 - project.Discovery
    catalog,  # noqa: ANN001 - scenario.ScenarioCatalog
    scenarios_with_a_verdict: set[str] | None = None,
) -> RiskReport:
    """Run every rule over an existing discovery, then triage the result.

    Takes the ``Discovery`` rather than a workspace path because the caller has
    already paid for it — the dashboard composes four planes from one walk — and
    because it keeps this module out of the business of deciding which directory
    is the project. That decision lives at the process boundary, in
    ``project/resolver.py``, and having two answers to it is how a path
    eventually gets accepted from a caller.
    """
    context = RuleContext(root=root, discovery=discovery)
    risks = triage(
        evaluate(context),
        catalog=catalog,
        scenarios_with_a_verdict=scenarios_with_a_verdict or set(),
    )
    return RiskReport(
        project_id=discovery.project_id, risks=risks, problems=context.problems
    )
