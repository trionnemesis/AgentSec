"""Scenario YAML loading and content addressing."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

from agentsec.errors import ScenarioError
from agentsec.models.scenario import Scenario


def _safe_load(path: Path) -> Any:
    try:
        # safe_load, not load: scenario files are attacker-adjacent content by
        # nature and must never be able to construct Python objects.
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ScenarioError(f"{path.name}: invalid YAML: {exc}") from exc
    except OSError as exc:
        raise ScenarioError(f"cannot read {path}: {exc}") from exc


def load_scenario_dict(path: Path) -> dict[str, Any]:
    data = _safe_load(path)
    if not isinstance(data, dict):
        raise ScenarioError(f"{path.name}: expected a mapping at the document root")
    return data


def load_scenario_file(path: Path) -> Scenario:
    """Parse and type-check a scenario file.

    Structural validation (JSON Schema) happens in the validator; this raises on
    anything Pydantic itself rejects so callers always get a real Scenario.
    """
    data = load_scenario_dict(path)
    try:
        return Scenario.model_validate(data)
    except Exception as exc:  # pydantic ValidationError, kept generic on purpose
        raise ScenarioError(f"{path.name}: {exc}") from exc


def resolve_payload(scenario_path: Path, payload_ref: str) -> str:
    """Read a payload_ref, refusing anything outside the scenario's directory.

    Scenario packs get shared between teams; a ``payload_ref: ../../../etc/passwd``
    should not read a file just because the harness happened to run as you.
    """
    base = scenario_path.parent.resolve()
    candidate = (base / payload_ref).resolve()
    if not candidate.is_relative_to(base):
        raise ScenarioError(
            f"payload_ref escapes the scenario directory: {payload_ref!r}",
            details={"scenario": scenario_path.name},
        )
    if not candidate.is_file():
        raise ScenarioError(f"payload_ref not found: {payload_ref!r}")
    return candidate.read_text(encoding="utf-8")


def scenario_digest(scenario: Scenario) -> str:
    """Content hash of the contract, stable across key ordering and comments.

    Stored on every run so a historical verdict can always be tied to the exact
    contract text that produced it, even after the YAML has moved on.
    """
    canonical = json.dumps(
        scenario.model_dump(mode="json", exclude_none=True),
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
