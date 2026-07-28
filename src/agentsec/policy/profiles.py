"""Run profiles: which scenarios run where, and which verdicts block a merge."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from agentsec.errors import ConfigError
from agentsec.models.run import PurpleVerdict

DEFAULT_PROFILES: dict[str, dict[str, object]] = {
    "pr": {
        "description": "Fast, non-destructive regression set for pull requests.",
        "max_duration_seconds": 600,
        "allow_destructive": False,
        "max_risk_level": "medium",
        "blocking_verdicts": ["error", "detection_gap", "prevention_gap"],
    },
    "nightly": {
        "description": "Full catalogue against staging.",
        "max_duration_seconds": 7200,
        "allow_destructive": False,
        "max_risk_level": "high",
        "blocking_verdicts": ["error", "detection_gap", "prevention_gap"],
    },
    "release": {
        "description": "Everything, including destructive scenarios, before a release.",
        "max_duration_seconds": 14400,
        "allow_destructive": True,
        "max_risk_level": "high",
        "blocking_verdicts": [
            "error", "detection_gap", "prevention_gap", "evidence_gap", "response_gap",
        ],
    },
}


class Profile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    description: str = ""
    max_duration_seconds: int = Field(default=3600, ge=1)
    allow_destructive: bool = False
    max_risk_level: Literal["low", "medium", "high"] = "medium"
    blocking_verdicts: list[PurpleVerdict] = Field(default_factory=list)

    def blocks(self, verdict: PurpleVerdict) -> bool:
        return verdict in self.blocking_verdicts


class ProfileSet(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    profiles: dict[str, Profile]

    def get(self, name: str) -> Profile:
        profile = self.profiles.get(name)
        if profile is None:
            raise ConfigError(
                f"unknown profile '{name}'",
                details={"known": sorted(self.profiles)},
            )
        return profile

    def names(self) -> list[str]:
        return sorted(self.profiles)


def _build(data: dict[str, dict[str, object]]) -> ProfileSet:
    return ProfileSet(
        profiles={
            name: Profile.model_validate({"name": name, **body}) for name, body in data.items()
        }
    )


def default_profiles() -> ProfileSet:
    return _build(DEFAULT_PROFILES)


def load_profiles(path: Path | None) -> ProfileSet:
    """Load profiles, falling back to the built-in set.

    A missing profiles.yaml is normal — most workspaces never need to override
    pr/nightly/release — so it is not an error.
    """
    if path is None or not path.is_file():
        return default_profiles()

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path.name}: invalid YAML: {exc}") from exc

    body = data.get("profiles") if isinstance(data, dict) else None
    if not isinstance(body, dict):
        raise ConfigError(f"{path.name}: expected a top-level 'profiles' mapping")

    merged = {**DEFAULT_PROFILES}
    for name, override in body.items():
        if not isinstance(override, dict):
            raise ConfigError(f"{path.name}: profile '{name}' must be a mapping")
        merged[name] = {**merged.get(name, {}), **override}

    try:
        return _build(merged)
    except Exception as exc:
        raise ConfigError(f"{path.name}: {exc}") from exc
