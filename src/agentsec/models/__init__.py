"""Typed models for every artefact that crosses a layer boundary.

Input contracts (Scenario, Target, Evidence) are authored as hand-written JSON
Schema under ``schemas/`` because humans write that YAML by hand and need good
validation errors. Output contracts (Run, Verdict, Finding) live here as Pydantic
models and their JSON Schema is *generated* (``make schemas``) so the two can
never drift apart.
"""

from agentsec.models.evidence import (
    Evidence,
    EvidenceWindow,
    OtelSpan,
    StateChange,
    ToolAuditRecord,
    TranscriptTurn,
    WazuhAlert,
)
from agentsec.models.finding import Finding, FindingStatus
from agentsec.models.fingerprint import (
    DevelopmentAgentConfig,
    FingerprintEvidence,
    FingerprintProblem,
    FingerprintReport,
    RuntimeAgentFingerprint,
)
from agentsec.models.run import (
    AxisResult,
    AxisStatus,
    CheckResult,
    ExecutionResult,
    PurpleVerdict,
    Run,
    RunStatus,
    Verdict,
)
from agentsec.models.scenario import (
    AttackStep,
    Contract,
    Scenario,
    ScenarioMetadata,
    ScenarioSpec,
    Severity,
)
from agentsec.models.target import Target, TargetAllowlist

__all__ = [
    "AttackStep",
    "AxisResult",
    "AxisStatus",
    "CheckResult",
    "Contract",
    "DevelopmentAgentConfig",
    "Evidence",
    "EvidenceWindow",
    "ExecutionResult",
    "Finding",
    "FindingStatus",
    "FingerprintEvidence",
    "FingerprintProblem",
    "FingerprintReport",
    "OtelSpan",
    "PurpleVerdict",
    "Run",
    "RunStatus",
    "RuntimeAgentFingerprint",
    "Scenario",
    "ScenarioMetadata",
    "ScenarioSpec",
    "Severity",
    "StateChange",
    "Target",
    "TargetAllowlist",
    "ToolAuditRecord",
    "TranscriptTurn",
    "Verdict",
    "WazuhAlert",
]
