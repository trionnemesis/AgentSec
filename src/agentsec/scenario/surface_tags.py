"""Which configuration surface does a scenario exercise, and which threat?

The scenario schema is ``extra="forbid"`` and has no dedicated field for this,
so the answer is carried on the existing ``metadata.tags`` extensibility point
with one convention:

    tags: ["config-surface:.claude/hooks/guard_agentsec.py"]

A tag naming a directory (``config-surface:.claude/agents``) covers every file
under it.

This module exists because two planes now ask the same surface question and
must not answer it differently. ``posture/coverage.py`` asks it of a static
scanner's finding; ``inspect/triage.py`` asks it of a risk this repository's
own rules raised. A surface that counts as covered for one and not the other
would make the dashboard contradict itself, so the path matching lives in one
place and both import it — ``scenarios_covering`` stays path-only for exactly
that reason.

The posture plane needs a second, narrower question the risk plane cannot yet
ask: not just "does a scenario exercise this file" but "does one exercise the
*threat* this finding claims". A :class:`~agentsec.models.risk.RepoRisk` (the
risk plane's input) carries no scanner-emitted category — it comes from this
repository's own deterministic rules, not from a static scanner report — so
there is nothing on it to match a ``threat-class:`` tag against. That is why
``scenarios_covering`` is not extended in place: it would grow a parameter
``inspect/triage.py`` has no value to pass. ``scenario_threat_classes`` and
``scenarios_matching_threat`` below exist only for the posture side, with the
convention:

    tags:
      - config-surface:.claude/hooks
      - threat-class:injection

``threat-class:<value>`` matches when ``<value>`` equals a finding's
scanner-emitted ``category``, compared after lowercasing and stripping
whitespace on both sides. Two reasons this matches on ``category`` and not on
the scanner's ``rule_id``:

* AgentShield's emitted finding id is per-instance, not a stable rule
  identifier — e.g. ``hooks-injection-${match.index}`` and
  ``agents-bash-access-${file.path}`` embed a byte offset or a file path.
  There is no fixed vocabulary a tag could name.
* Even the *rule* id would not help: upstream picks a finding's category per
  branch inside a rule, not once per rule, so one rule routinely emits
  findings of more than one category (e.g. ``hooks-sensitive-file-access`` is
  a ``hooks``-categorised rule that emits an ``exposure`` finding). Matching
  on ``rule_id`` would require an AgentSec-maintained rule -> threat table
  that drifts against a 100+-rule upstream every time a branch is added —
  precisely the hand-copied mapping this design avoids.

``category`` is, by contrast, data the scanner already emits and the adapter
already normalises onto :class:`~agentsec.models.posture.StaticPostureFinding`
verbatim, with no AgentSec-side vocabulary of any kind. A scanner that emits
no category normalises to ``"uncategorised"`` (``posture/adapter.py``); no
``threat-class:`` tag may ever be given that value, because that would
convert "the scanner told us nothing" into "covered" — the exact defect this
module removes, re-entered through the tag. The semantic degrades safely for
a scanner that never emits categories at all (e.g. CodeQL, Semgrep SARIF):
every finding lands on ``uncategorised``, nobody tags it, so it simply stays
``not_tested`` rather than over-claiming.

Known limit, documented rather than fixed: for SARIF, ``posture/adapter.py``
prefers a result's rule-level ``properties.category`` over the result's own
``properties.category``. That is harmless for AgentShield, whose finding ids
are per-instance so the "rule" descriptor is effectively per-finding too — but
a generic SARIF producer whose ``ruleId`` is a true, shared rule id would have
its first result's category attributed to every other result under that same
rule. No such producer is wired today; if one is, this precedence needs
revisiting alongside it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle
    from agentsec.scenario.catalog import ScenarioCatalog

CONFIG_SURFACE_TAG_PREFIX = "config-surface:"
THREAT_CLASS_TAG_PREFIX = "threat-class:"


def under(file_path: str, surface_path: str) -> bool:
    """True if ``file_path`` is ``surface_path`` or lives under it as a directory."""
    return file_path == surface_path or file_path.startswith(surface_path.rstrip("/") + "/")


def scenario_surface_tags(catalog: ScenarioCatalog) -> dict[str, list[str]]:
    """scenario_id -> the config-surface paths/prefixes its tags declare.

    Scenarios that declare no surface are absent rather than present-and-empty:
    every caller is asking "what covers this file", and an entry that covers
    nothing is only a chance to accidentally match.
    """
    out: dict[str, list[str]] = {}
    for entry in catalog:
        surfaces = [
            tag[len(CONFIG_SURFACE_TAG_PREFIX):]
            for tag in entry.scenario.metadata.tags
            if tag.startswith(CONFIG_SURFACE_TAG_PREFIX)
        ]
        if surfaces:
            out[entry.id] = surfaces
    return out


def scenarios_covering(file_path: str, surface_tags: dict[str, list[str]]) -> list[str]:
    """Sorted scenario ids whose declared surfaces contain ``file_path``.

    Path-only, deliberately: this is also called by ``inspect/triage.py`` for
    a ``RepoRisk``, which has no scanner-emitted category to narrow by. Do not
    add a threat parameter here — see the module docstring.
    """
    return sorted(
        scenario_id
        for scenario_id, surfaces in surface_tags.items()
        if any(under(file_path, surface) for surface in surfaces)
    )


def scenario_threat_classes(catalog: ScenarioCatalog) -> dict[str, set[str]]:
    """scenario_id -> the lowercased, whitespace-stripped ``threat-class:``
    values its tags declare.

    Scenarios that declare none are absent rather than present-and-empty, for
    the same reason as :func:`scenario_surface_tags`: a caller is asking
    "which threat does this scenario settle", and an entry that settles none
    is only a chance to accidentally match.

    Returns ``set[str]`` where :func:`scenario_surface_tags` returns
    ``list[str]`` — a deliberate difference, not an inconsistency to
    "harmonise" later. A surface tag is matched with :func:`under`, a
    prefix/equality predicate applied per element, so a list of the raw
    strings is all that predicate needs. A threat-class tag is matched with
    plain equality against one already-normalised finding category, which is
    exactly what a set gives for free: de-duplication of a repeated tag and
    O(1) membership, with no per-element predicate to run.
    """
    out: dict[str, set[str]] = {}
    for entry in catalog:
        threats = {
            tag[len(THREAT_CLASS_TAG_PREFIX):].strip().lower()
            for tag in entry.scenario.metadata.tags
            if tag.startswith(THREAT_CLASS_TAG_PREFIX)
        }
        if threats:
            out[entry.id] = threats
    return out


def scenarios_matching_threat(
    file_path: str,
    category: str,
    surface_tags: dict[str, list[str]],
    threat_tags: dict[str, set[str]],
) -> list[str]:
    """Sorted scenario ids whose declared surface contains ``file_path`` AND
    whose declared threat class matches ``category``.

    ``category`` is compared lowercased and whitespace-stripped, the same
    normalisation applied when ``threat_tags`` was built by
    :func:`scenario_threat_classes` — see the module docstring for why this
    matches on category rather than ``rule_id``, and why ``uncategorised``
    must never be written as a tag. A scenario present in ``surface_tags`` but
    absent from ``threat_tags`` (a ``config-surface:`` with no ``threat-class:``
    at all) never matches here — an unstated threat settles nothing.
    """
    normalised_category = category.strip().lower()
    return sorted(
        scenario_id
        for scenario_id, surfaces in surface_tags.items()
        if any(under(file_path, surface) for surface in surfaces)
        and normalised_category in threat_tags.get(scenario_id, set())
    )
