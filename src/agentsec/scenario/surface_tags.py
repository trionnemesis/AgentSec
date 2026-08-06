"""Which configuration surface does a scenario exercise?

The scenario schema is ``extra="forbid"`` and has no dedicated field for this,
so the answer is carried on the existing ``metadata.tags`` extensibility point
with one convention:

    tags: ["config-surface:.claude/hooks/guard_agentsec.py"]

A tag naming a directory (``config-surface:.claude/agents``) covers every file
under it.

This module exists because two planes now ask the same question and must not
answer it differently. ``posture/coverage.py`` asks it of a static scanner's
finding; ``inspect/triage.py`` asks it of a risk this repository's own rules
raised. A surface that counts as covered for one and not the other would make
the dashboard contradict itself, so the matching lives in one place and both
import it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle
    from agentsec.scenario.catalog import ScenarioCatalog

CONFIG_SURFACE_TAG_PREFIX = "config-surface:"


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
    """Sorted scenario ids whose declared surfaces contain ``file_path``."""
    return sorted(
        scenario_id
        for scenario_id, surfaces in surface_tags.items()
        if any(under(file_path, surface) for surface in surfaces)
    )
