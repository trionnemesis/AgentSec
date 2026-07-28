"""Target allowlist model.

The single place where a concrete endpoint or credential *name* is written down.
Callers — including Claude — reference a target by id and cannot supply a URL.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.models.scenario import Capability, Environment, ExecutorName, RiskLevel


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Adapter(_Base):
    kind: Literal["http", "fixture"]
    base_url: str | None = None
    chat_path: str = "/chat"
    headers_from_env: dict[str, str] = Field(default_factory=dict)
    fixture_dir: str | None = None
    timeout_seconds: int = Field(default=60, ge=1, le=600)

    @model_validator(mode="after")
    def _require_locator(self) -> Adapter:
        if self.kind == "http" and not self.base_url:
            raise ValueError("adapter kind=http requires base_url")
        if self.kind == "fixture" and not self.fixture_dir:
            raise ValueError("adapter kind=fixture requires fixture_dir")
        return self


class OtelBackend(_Base):
    kind: Literal["file", "http", "none"]
    path: str | None = None
    url: str | None = None
    service_name: str | None = None


class WazuhBackend(_Base):
    kind: Literal["file", "opensearch", "none"]
    path: str | None = None
    url: str | None = None
    index: str = "wazuh-alerts-*"
    username_env: str | None = None
    password_env: str | None = None
    verify_tls: bool = True


class ToolAuditBackend(_Base):
    kind: Literal["file", "http", "none"]
    path: str | None = None
    url: str | None = None


class StateDiffBackend(_Base):
    kind: Literal["file", "http", "none"]
    path: str | None = None
    url: str | None = None
    collections: list[str] = Field(default_factory=list)


class EvidenceBackends(_Base):
    otel: OtelBackend | None = None
    wazuh: WazuhBackend | None = None
    tool_audit: ToolAuditBackend | None = None
    state_diff: StateDiffBackend | None = None


class RateLimit(_Base):
    max_runs_per_hour: int = Field(default=20, ge=1)
    max_concurrent_runs: int = Field(default=1, ge=1)


class Target(_Base):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    environment: Environment
    adapter: Adapter
    description: str | None = None
    capabilities: list[Capability] = Field(default_factory=list)
    max_risk_level: RiskLevel = RiskLevel.MEDIUM
    allow_destructive: bool = False
    allowed_executors: list[ExecutorName] = Field(default=["replay"])
    principals: dict[str, str] = Field(default_factory=dict)
    evidence: EvidenceBackends = Field(default_factory=EvidenceBackends)
    rate_limit: RateLimit = Field(default_factory=RateLimit)

    def redacted(self) -> dict[str, object]:
        """Projection safe to hand to an LLM or a read-only gateway.

        Endpoints and credential variable names are both withheld: knowing that
        a target reads ``ORDER_AGENT_TOKEN`` is a hint worth not giving away.
        """
        return {
            "id": self.id,
            "description": self.description,
            "environment": self.environment,
            "capabilities": list(self.capabilities),
            "max_risk_level": str(self.max_risk_level),
            "allow_destructive": self.allow_destructive,
            "allowed_executors": list(self.allowed_executors),
            "principals": sorted(self.principals),
            "evidence_backends": sorted(
                name
                for name in ("otel", "wazuh", "tool_audit", "state_diff")
                if getattr(self.evidence, name) is not None
                and getattr(self.evidence, name).kind != "none"
            ),
        }


class TargetAllowlist(_Base):
    apiVersion: Literal["agentsec.dev/v1"] = "agentsec.dev/v1"
    kind: Literal["TargetAllowlist"] = "TargetAllowlist"
    targets: list[Target] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_ids(self) -> TargetAllowlist:
        ids = [t.id for t in self.targets]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"duplicate target ids: {sorted(dupes)}")
        return self

    def get(self, target_id: str) -> Target | None:
        for t in self.targets:
            if t.id == target_id:
                return t
        return None
