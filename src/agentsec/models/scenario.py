"""Scenario model — the Attack-Detection Contract.

This is the asset that survives a change of AI vendor, SIEM or test runner.
Everything else in the harness is an implementation detail behind it.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


RISK_ORDER: dict[RiskLevel, int] = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2}

Environment = Literal["local", "ci", "staging"]
Capability = Literal[
    "rag", "tool_calling", "memory", "multi_tenant", "code_exec", "email", "payments"
]
ExecutorName = Literal["replay", "promptfoo", "pyrit", "pytest"]
Decision = Literal["allow", "deny", "escalate"]


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class References(_Base):
    owasp_agentic: list[str] = Field(default_factory=list)
    owasp_llm: list[str] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    mitre_atlas: list[str] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)


class ScenarioMetadata(_Base):
    id: str = Field(pattern=r"^AGT-[A-Z0-9]+-\d{3}$")
    title: str = Field(min_length=8, max_length=160)
    description: str | None = None
    owner: str | None = None
    severity: Severity
    tags: list[str] = Field(default_factory=list)
    references: References = Field(default_factory=References)


class TargetSelector(_Base):
    environments: list[Environment] = Field(min_length=1)
    capabilities: list[Capability] = Field(default_factory=list)
    target_ids: list[str] = Field(default_factory=list)


class Risk(_Base):
    level: RiskLevel
    destructive: bool = False
    requires_approval: bool = False
    data_classes_touched: list[
        Literal["synthetic", "pseudonymised", "internal", "pii", "secret"]
    ] = Field(default=["synthetic"])

    @model_validator(mode="after")
    def _destructive_implies_approval(self) -> Risk:
        # A destructive scenario that does not require approval is a footgun,
        # so we upgrade rather than reject: authors forget, and silently
        # running it would be worse than silently making it stricter.
        if self.destructive and not self.requires_approval:
            object.__setattr__(self, "requires_approval", True)
        return self


class AttackStep(_Base):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    kind: Literal[
        "agent_message",
        "seed_resource",
        "seed_memory",
        "tool_response_injection",
        "assume_identity",
        "wait",
        "snapshot_state",
    ]
    description: str | None = None
    as_principal: str | None = None
    payload: str | dict[str, Any] | None = None
    payload_ref: str | None = None
    seconds: float | None = Field(default=None, ge=0, le=600)

    @model_validator(mode="after")
    def _payload_exclusivity(self) -> AttackStep:
        if self.payload is not None and self.payload_ref is not None:
            raise ValueError(f"step '{self.id}': set payload or payload_ref, not both")
        return self


class Attack(_Base):
    executor: ExecutorName
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    config: dict[str, Any] = Field(default_factory=dict)
    steps: list[AttackStep] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_step_ids(self) -> Attack:
        ids = [s.id for s in self.steps]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"duplicate step ids: {sorted(dupes)}")
        return self


class BehaviourAssertion(_Base):
    kind: Literal[
        "tool_call", "output_contains", "output_matches", "policy_decision",
        "state_change", "http_egress",
    ]
    tool: str | None = None
    value: str | None = None
    decision: Decision | None = None
    resource: str | None = None
    case_sensitive: bool = False
    reason: str | None = None

    # Scope. Without these, an output assertion matches the whole transcript,
    # which silently breaks any multi-principal scenario: a legitimate turn as
    # tenant B that mentions an order id would trip a `must_not` aimed at
    # tenant A. Scoping makes the assertion say what the author meant.
    in_step: str | None = None
    as_principal: str | None = None

    def describe(self) -> str:
        bits: list[str] = [self.kind]
        for label, val in (
            ("tool", self.tool),
            ("value", self.value),
            ("decision", self.decision),
            ("resource", self.resource),
            ("in_step", self.in_step),
            ("as_principal", self.as_principal),
        ):
            if val is not None:
                bits.append(f"{label}={val!r}")
        return " ".join(bits)

    @property
    def is_scoped(self) -> bool:
        return self.in_step is not None or self.as_principal is not None


class PreventionContract(_Base):
    must_not: list[BehaviourAssertion] = Field(default_factory=list)
    must: list[BehaviourAssertion] = Field(default_factory=list)


class AlertAssertion(_Base):
    rule_id: str | None = None
    rule_group: str | None = None
    min_level: int | None = Field(default=None, ge=0, le=16)
    within_seconds: int = Field(default=300, ge=1, le=3600)
    match_fields: dict[str, str] = Field(default_factory=dict)
    reason: str | None = None

    def describe(self) -> str:
        bits = []
        if self.rule_id:
            bits.append(f"rule_id={self.rule_id}")
        if self.rule_group:
            bits.append(f"group={self.rule_group}")
        if self.min_level is not None:
            bits.append(f"level>={self.min_level}")
        for k, v in sorted(self.match_fields.items()):
            bits.append(f"{k}={v!r}")
        return "wazuh alert " + (" ".join(bits) or "(any)")


class SpanAssertion(_Base):
    name: str
    attributes: dict[str, str | int | float | bool] = Field(default_factory=dict)
    min_count: int = Field(default=1, ge=1)
    status: Literal["unset", "ok", "error"] | None = None
    reason: str | None = None

    def describe(self) -> str:
        bits = [f"span {self.name!r}"]
        for k, v in sorted(self.attributes.items()):
            bits.append(f"{k}={v!r}")
        if self.status:
            bits.append(f"status={self.status}")
        if self.min_count > 1:
            bits.append(f"x{self.min_count}")
        return " ".join(bits)


class WazuhDetection(_Base):
    must_fire: list[AlertAssertion] = Field(default_factory=list)
    must_not_fire: list[AlertAssertion] = Field(default_factory=list)


class OtelDetection(_Base):
    must_emit: list[SpanAssertion] = Field(default_factory=list)


class DetectionContract(_Base):
    wazuh: WazuhDetection | None = None
    otel: OtelDetection | None = None


class ToolAuditAssertion(_Base):
    tool: str | None = None
    decision: Decision | None = None
    principal: str | None = None
    min_count: int = Field(default=1, ge=1)
    reason: str | None = None

    def describe(self) -> str:
        bits = ["tool audit"]
        for label, val in (
            ("tool", self.tool), ("decision", self.decision), ("principal", self.principal)
        ):
            if val is not None:
                bits.append(f"{label}={val!r}")
        if self.min_count > 1:
            bits.append(f"x{self.min_count}")
        return " ".join(bits)


class StateChangeAssertion(_Base):
    collection: str | None = None
    operation: Literal["insert", "update", "delete"] | None = None
    selector: dict[str, str] = Field(default_factory=dict)
    reason: str | None = None

    def describe(self) -> str:
        bits = ["state change"]
        if self.collection:
            bits.append(f"collection={self.collection!r}")
        if self.operation:
            bits.append(f"op={self.operation}")
        for k, v in sorted(self.selector.items()):
            bits.append(f"{k}={v!r}")
        return " ".join(bits)


class OtelEvidence(_Base):
    required_spans: list[SpanAssertion] = Field(default_factory=list)
    trace_must_be_complete: bool = False


class ToolAuditEvidence(_Base):
    required_records: list[ToolAuditAssertion] = Field(default_factory=list)
    every_tool_call_audited: bool = True


class StateDiffEvidence(_Base):
    must_be_empty: bool | None = None
    allowed_changes: list[StateChangeAssertion] = Field(default_factory=list)
    forbidden_changes: list[StateChangeAssertion] = Field(default_factory=list)


class EvidenceContract(_Base):
    otel: OtelEvidence | None = None
    tool_audit: ToolAuditEvidence | None = None
    state_diff: StateDiffEvidence | None = None


class ExpectedAction(_Base):
    action: Literal[
        "revoke_credential", "quarantine_session", "disable_tool", "page_oncall",
        "block_principal",
    ]
    within_seconds: int = Field(default=300, ge=1, le=3600)
    reason: str | None = None


class ResponseContract(_Base):
    mode: Literal["not_tested", "manual_runbook", "automated"] = "not_tested"
    runbook: str | None = None
    expected_actions: list[ExpectedAction] = Field(default_factory=list)


class Contract(_Base):
    prevention: PreventionContract | None = None
    detection: DetectionContract | None = None
    evidence: EvidenceContract | None = None
    response: ResponseContract | None = None


class Regression(_Base):
    ci_profiles: list[Literal["pr", "nightly", "release"]] = Field(default=["nightly"])
    gate: Literal["blocking", "warning", "off"] = "warning"
    linked_finding: str | None = None
    quarantined_until: str | None = None


class ScenarioSpec(_Base):
    target: TargetSelector
    risk: Risk
    attack: Attack
    contract: Contract
    regression: Regression = Field(default_factory=Regression)


class Scenario(_Base):
    apiVersion: Literal["agentsec.dev/v1"] = "agentsec.dev/v1"
    kind: Literal["Scenario"] = "Scenario"
    metadata: ScenarioMetadata
    spec: ScenarioSpec

    @property
    def id(self) -> str:
        return self.metadata.id

    @property
    def tested_axes(self) -> list[str]:
        """Axes this scenario actually asserts on. An omitted axis is not_tested."""
        c = self.spec.contract
        axes = []
        if c.prevention and (c.prevention.must or c.prevention.must_not):
            axes.append("prevention")
        if c.detection and (c.detection.wazuh or c.detection.otel):
            axes.append("detection")
        if c.evidence and (c.evidence.otel or c.evidence.tool_audit or c.evidence.state_diff):
            axes.append("evidence")
        if c.response and c.response.mode != "not_tested":
            axes.append("response")
        return axes
