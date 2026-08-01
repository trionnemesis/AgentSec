"""Workspace layout and settings.

A "workspace" is a directory holding scenarios, policy and results. The CLI, the
MCP gateway and CI all point at the same workspace, which is how they stay
consistent without sharing a process.

The root itself is resolved by :func:`agentsec.project.resolver.resolve_root`,
which is also what project discovery uses. One canonicalisation, one set of
checks: a root that is refused for discovery cannot be accepted for execution.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from agentsec.errors import ConfigError
from agentsec.project.resolver import ENV_WORKSPACE, resolve_root

#: Re-exported: callers have always imported it from here.
__all__ = ["ENV_ACTOR", "ENV_DB", "ENV_WORKSPACE", "Settings", "load_settings",
           "package_schema_dir"]

ENV_DB = "AGENTSEC_DB"
ENV_ACTOR = "AGENTSEC_ACTOR"


@dataclass(frozen=True)
class Settings:
    workspace: Path
    scenarios_dir: Path
    policy_dir: Path
    results_dir: Path
    db_path: Path
    actor: str

    @property
    def targets_file(self) -> Path:
        return self.policy_dir / "targets.yaml"

    @property
    def profiles_file(self) -> Path:
        return self.policy_dir / "profiles.yaml"

    @property
    def approvals_file(self) -> Path:
        return self.policy_dir / "approvals.yaml"

    @property
    def evidence_dir(self) -> Path:
        return self.results_dir / "evidence"

    @property
    def raw_dir(self) -> Path:
        return self.results_dir / "raw"

    @property
    def reports_dir(self) -> Path:
        return self.results_dir / "reports"

    def ensure_dirs(self) -> None:
        for d in (self.results_dir, self.evidence_dir, self.raw_dir, self.reports_dir):
            d.mkdir(parents=True, exist_ok=True)


def load_settings(workspace: str | Path | None = None) -> Settings:
    root = resolve_root(workspace)

    db_env = os.environ.get(ENV_DB)
    db_path = Path(db_env).resolve() if db_env else root / "results" / "agentsec.db"

    return Settings(
        workspace=root,
        scenarios_dir=root / "scenarios",
        policy_dir=root / "policy",
        results_dir=root / "results",
        db_path=db_path,
        actor=os.environ.get(ENV_ACTOR, "cli"),
    )


def package_schema_dir() -> Path:
    """Locate bundled JSON Schemas, whether running from a wheel or a checkout."""
    installed = Path(__file__).parent / "_data" / "schemas"
    if installed.is_dir():
        return installed
    checkout = Path(__file__).resolve().parents[2] / "schemas"
    if checkout.is_dir():
        return checkout
    raise ConfigError("cannot locate bundled JSON schemas")
