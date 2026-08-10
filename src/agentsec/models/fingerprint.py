"""Evidence-backed classification of AI-agent code in a repository.

This model deliberately separates runtime code from development-agent
configuration.  A ``CLAUDE.md`` or ``.mcp.json`` changes how a coding agent
works on a checkout; neither proves that the application in the checkout is an
AI agent.  Keeping the two lists distinct makes that overclaim impossible for
callers that render this object faithfully.

The detector records only bounded structural facts: dependency names, import
names, builder symbols and relative paths.  It never carries source text.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

AgentPresence = Literal[
    "confirmed",
    "likely",
    "configuration_only",
    "not_detected",
    "unsupported",
]
FingerprintConfidence = Literal["high", "medium", "none"]
EvidenceKind = Literal[
    "dependency", "import", "builder_call", "runtime_config", "tool_calling"
]
FingerprintLanguage = Literal["python", "javascript", "typescript", "mixed", "unknown"]
DevelopmentPlatform = Literal["claude_code", "codex", "gemini_cli", "cursor", "mcp"]
FingerprintProblemKind = Literal[
    "invalid_manifest",
    "undecodable",
    "too_large",
    "syntax_error",
    "outside_root_symlink",
    "symlink_skipped",
    "scan_limit",
]


class FingerprintEvidence(BaseModel):
    """One bounded fact used to classify a runtime candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: EvidenceKind
    file: str
    value: str


class RuntimeAgentFingerprint(BaseModel):
    """A recognised framework or a framework-neutral tool-calling path."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    framework: str
    language: FingerprintLanguage
    confidence: Literal["high", "medium"]
    entrypoints: list[str] = Field(default_factory=list)
    evidence: list[FingerprintEvidence] = Field(default_factory=list)


class DevelopmentAgentConfig(BaseModel):
    """Configuration for a coding agent, kept outside runtime fingerprints."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    platform: DevelopmentPlatform
    paths: list[str] = Field(default_factory=list)


class FingerprintProblem(BaseModel):
    """A candidate input the detector could not inspect completely."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    kind: FingerprintProblemKind
    detail: str


class FingerprintReport(BaseModel):
    """The deterministic result of statically fingerprinting one checkout."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.0.0"
    agent_presence: AgentPresence
    confidence: FingerprintConfidence
    runtime_agents: list[RuntimeAgentFingerprint] = Field(default_factory=list)
    development_agent_config: list[DevelopmentAgentConfig] = Field(default_factory=list)
    problems: list[FingerprintProblem] = Field(default_factory=list)

    @model_validator(mode="after")
    def _status_matches_evidence(self) -> FingerprintReport:
        high = any(item.confidence == "high" for item in self.runtime_agents)
        if self.agent_presence == "confirmed" and (not high or self.confidence != "high"):
            raise ValueError("confirmed requires high confidence and a high-confidence runtime")
        if self.agent_presence == "likely" and (
            not self.runtime_agents or high or self.confidence != "medium"
        ):
            raise ValueError("likely requires only medium-confidence runtime fingerprints")
        if self.agent_presence == "configuration_only" and (
            self.runtime_agents
            or not self.development_agent_config
            or self.confidence != "medium"
        ):
            raise ValueError(
                "configuration_only requires development config and no runtime fingerprint"
            )
        if self.agent_presence == "not_detected" and (
            self.runtime_agents
            or self.development_agent_config
            or self.confidence != "none"
        ):
            raise ValueError("not_detected cannot carry runtime or development-agent evidence")
        if self.agent_presence == "unsupported" and (
            not self.problems or self.runtime_agents or self.confidence != "none"
        ):
            raise ValueError(
                "unsupported requires an incomplete classification and no runtime claim"
            )
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
