"""Scenario catalog: discovery, lookup and coverage."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from agentsec.errors import ScenarioError, ScenarioNotFound
from agentsec.models.scenario import Scenario
from agentsec.models.target import Target
from agentsec.scenario.loader import load_scenario_file

#: OWASP Agentic AI Top 10 (2025). Used as the coverage denominator so an empty
#: catalog reports 0% against a real target instead of a flattering 100%.
OWASP_AGENTIC_TOP10: dict[str, str] = {
    "AAI001": "Agent Goal & Instruction Manipulation",
    "AAI002": "Tool Misuse & Exploitation",
    "AAI003": "Identity & Privilege Abuse",
    "AAI004": "Memory & Context Poisoning",
    "AAI005": "Agent Orchestration & Multi-Agent Exploitation",
    "AAI006": "Unsafe Code & Command Execution",
    "AAI007": "Supply Chain & Dependency Attacks",
    "AAI008": "Insufficient Observability & Traceability",
    "AAI009": "Resource Exhaustion & Denial of Wallet",
    "AAI010": "Human-Agent Trust Exploitation",
}


@dataclass(frozen=True)
class CatalogEntry:
    scenario: Scenario
    path: Path

    @property
    def id(self) -> str:
        return self.scenario.id


class ScenarioCatalog:
    """Loads every scenario under a directory and indexes it by id."""

    def __init__(self, entries: list[CatalogEntry], load_errors: list[str] | None = None) -> None:
        self._entries = {e.id: e for e in entries}
        self.load_errors = load_errors or []

    @classmethod
    def from_dir(cls, directory: Path, *, strict: bool = False) -> ScenarioCatalog:
        entries: list[CatalogEntry] = []
        errors: list[str] = []
        if not directory.is_dir():
            return cls([], [f"scenario directory not found: {directory}"])

        for path in sorted(directory.rglob("*.y*ml")):
            try:
                entries.append(CatalogEntry(load_scenario_file(path), path))
            except ScenarioError as exc:
                # One malformed file must not hide the other forty. Collect and
                # carry on unless the caller explicitly asked for strict loading.
                if strict:
                    raise
                errors.append(str(exc))

        seen: dict[str, Path] = {}
        for e in entries:
            if e.id in seen:
                msg = f"duplicate scenario id '{e.id}' in {e.path.name} and {seen[e.id].name}"
                if strict:
                    raise ScenarioError(msg)
                errors.append(msg)
            seen[e.id] = e.path

        return cls(entries, errors)

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[CatalogEntry]:
        return iter(self._entries.values())

    def __contains__(self, scenario_id: object) -> bool:
        return scenario_id in self._entries

    def ids(self) -> list[str]:
        return sorted(self._entries)

    def get(self, scenario_id: str) -> Scenario:
        entry = self._entries.get(scenario_id)
        if entry is None:
            raise ScenarioNotFound(
                f"unknown scenario '{scenario_id}'",
                details={"known": self.ids()[:20]},
            )
        return entry.scenario

    def path_of(self, scenario_id: str) -> Path:
        entry = self._entries.get(scenario_id)
        if entry is None:
            raise ScenarioNotFound(f"unknown scenario '{scenario_id}'")
        return entry.path

    def select(
        self,
        *,
        profile: str | None = None,
        target: Target | None = None,
        scenario_ids: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> list[Scenario]:
        """Resolve a run request into a concrete, ordered scenario list.

        Selection is intentionally silent about *why* something was excluded;
        callers that need reasons should validate each scenario against the
        target instead, which reports every mismatch.
        """
        if scenario_ids:
            chosen = [self.get(sid) for sid in scenario_ids]
        else:
            chosen = [e.scenario for e in self]

        if profile:
            chosen = [s for s in chosen if profile in s.spec.regression.ci_profiles]
        if tags:
            wanted = set(tags)
            chosen = [s for s in chosen if wanted & set(s.metadata.tags)]
        if target is not None:
            chosen = [s for s in chosen if self._applies_to(s, target)]

        return sorted(chosen, key=lambda s: s.id)

    @staticmethod
    def _applies_to(s: Scenario, t: Target) -> bool:
        from agentsec.models.scenario import RISK_ORDER

        if t.environment not in s.spec.target.environments:
            return False
        if set(s.spec.target.capabilities) - set(t.capabilities):
            return False
        if s.spec.target.target_ids and t.id not in s.spec.target.target_ids:
            return False
        if s.spec.attack.executor not in t.allowed_executors:
            return False
        if RISK_ORDER[s.spec.risk.level] > RISK_ORDER[t.max_risk_level]:
            return False
        return not (s.spec.risk.destructive and not t.allow_destructive)

    def coverage(self) -> dict[str, object]:
        """Coverage against the OWASP Agentic Top 10."""
        by_category: dict[str, list[str]] = {k: [] for k in OWASP_AGENTIC_TOP10}
        unmapped: list[str] = []

        for entry in self:
            refs = entry.scenario.metadata.references.owasp_agentic
            if not refs:
                unmapped.append(entry.id)
                continue
            for ref in refs:
                by_category.setdefault(ref, []).append(entry.id)

        covered = sum(1 for k in OWASP_AGENTIC_TOP10 if by_category.get(k))
        return {
            "framework": "OWASP Agentic AI Top 10 (2025)",
            "categories": [
                {
                    "id": cid,
                    "title": title,
                    "covered": bool(by_category.get(cid)),
                    "scenario_ids": sorted(by_category.get(cid, [])),
                }
                for cid, title in OWASP_AGENTIC_TOP10.items()
            ],
            "covered_categories": covered,
            "total_categories": len(OWASP_AGENTIC_TOP10),
            "coverage_ratio": round(covered / len(OWASP_AGENTIC_TOP10), 3),
            "unmapped_scenarios": sorted(unmapped),
            "total_scenarios": len(self),
        }
