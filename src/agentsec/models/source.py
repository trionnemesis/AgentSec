"""Frozen contract/package identity, separate from evidence origin and verdicts."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SourceProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    package_version: str | None = None
    package_commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    catalogue_origin: Literal["builtin", "workspace"]
    catalogue_ref: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    catalogue_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    scenario_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
