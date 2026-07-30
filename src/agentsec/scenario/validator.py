"""Scenario validation.

Three layers, in order:

1. JSON Schema  — shape and enums, with good messages for hand-written YAML.
2. Pydantic     — types and cross-field rules.
3. Semantic     — the checks that actually stop bad purple tests getting merged,
                  e.g. "you asserted nothing", or "this only tests prevention".

Layer 3 is the one worth reading. A scenario that passes schema validation but
asserts nothing is worse than no scenario: it shows up green on the coverage
dashboard forever.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from jsonschema import Draft202012Validator

from agentsec.config import package_schema_dir
from agentsec.models.scenario import Scenario
from agentsec.models.target import Target

Level = Literal["error", "warning", "info"]


@dataclass(frozen=True)
class ValidationIssue:
    level: Level
    code: str
    message: str
    path: str = ""

    def render(self) -> str:
        loc = f" at {self.path}" if self.path else ""
        return f"[{self.level}] {self.code}{loc}: {self.message}"


@dataclass
class ValidationReport:
    scenario_id: str | None = None
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.level == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors

    def add(self, level: Level, code: str, message: str, path: str = "") -> None:
        self.issues.append(ValidationIssue(level, code, message, path))

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "valid": self.ok,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "issues": [
                {"level": i.level, "code": i.code, "message": i.message, "path": i.path}
                for i in self.issues
            ],
        }


@lru_cache(maxsize=8)
def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((package_schema_dir() / name).read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def validate_scenario_dict(data: dict[str, Any]) -> ValidationReport:
    """Layer 1: JSON Schema only. Used for fast feedback on raw YAML."""
    report = ValidationReport(scenario_id=_peek_id(data))
    for err in sorted(_validator("scenario.schema.json").iter_errors(data), key=str):
        path = "/".join(str(p) for p in err.absolute_path) or "(root)"
        report.add("error", "schema", err.message, path)
    return report


def validate_scenario(
    scenario: Scenario,
    *,
    target: Target | None = None,
    raw: dict[str, Any] | None = None,
) -> ValidationReport:
    """Full validation. Pass ``target`` to also check applicability."""
    report = ValidationReport(scenario_id=scenario.id)

    if raw is not None:
        report.issues.extend(validate_scenario_dict(raw).issues)

    _check_contract_is_meaningful(scenario, report)
    _check_purple_balance(scenario, report)
    _check_assertions_are_evaluatable(scenario, report)
    _check_steps(scenario, report)
    _check_risk_coherence(scenario, report)
    _check_references(scenario, report)

    if target is not None:
        _check_applicability(scenario, target, report)

    return report


def _peek_id(data: dict[str, Any]) -> str | None:
    meta = data.get("metadata")
    return meta.get("id") if isinstance(meta, dict) else None


def _check_contract_is_meaningful(s: Scenario, r: ValidationReport) -> None:
    if not s.tested_axes:
        r.add(
            "error",
            "empty_contract",
            "the contract asserts nothing, so every run would report secure. "
            "Add at least one prevention/detection/evidence assertion.",
            "spec/contract",
        )


def _check_purple_balance(s: Scenario, r: ValidationReport) -> None:
    axes = set(s.tested_axes)

    if axes == {"prevention"}:
        r.add(
            "warning",
            "red_only",
            "this scenario only checks prevention. Without a detection assertion "
            "a silent bypass is indistinguishable from a fix — add a detection "
            "or evidence expectation to make it a purple test.",
            "spec/contract/detection",
        )

    if "detection" in axes and "evidence" not in axes:
        r.add(
            "info",
            "no_evidence_axis",
            "an alert fires but nothing asserts that an investigator could "
            "reconstruct the incident afterwards.",
            "spec/contract/evidence",
        )

    det = s.spec.contract.detection
    if det and det.wazuh and not det.wazuh.must_fire and not det.wazuh.must_not_fire:
        r.add("warning", "empty_wazuh_block", "wazuh detection block has no assertions",
              "spec/contract/detection/wazuh")


def _check_assertions_are_evaluatable(s: Scenario, r: ValidationReport) -> None:
    """Catch assertions that cannot be evaluated at all.

    An ``output_contains`` with no ``value`` used to look harmless: nothing could
    be found, so the behaviour "did not occur", so every ``must_not`` containing
    it passed. The evaluator now raises on this, but catching it at authoring
    time is where it belongs.
    """
    prevention = s.spec.contract.prevention
    if prevention is None:
        return

    for group_name, group in (("must_not", prevention.must_not), ("must", prevention.must)):
        for i, assertion in enumerate(group):
            path = f"spec/contract/prevention/{group_name}/{i}"
            if assertion.kind in {"output_contains", "output_matches"} and not assertion.value:
                r.add("error", "output_assertion_without_value",
                      f"{assertion.kind} needs a 'value' to look for", path)
            if assertion.kind == "output_matches" and assertion.value:
                import re

                try:
                    re.compile(assertion.value)
                except re.error as exc:
                    r.add("error", "invalid_regex",
                          f"output_matches pattern is not a valid regex: {exc}", path)
            if assertion.kind in {"tool_call", "policy_decision"} and not assertion.tool:
                r.add("warning", "unscoped_tool_assertion",
                      f"{assertion.kind} with no 'tool' matches any tool, which is "
                      "almost never what the author meant", path)
            if assertion.kind == "state_change" and not assertion.resource:
                r.add("warning", "unscoped_state_assertion",
                      "state_change with no 'resource' matches any collection", path)
            if assertion.kind == "http_egress" and not assertion.resource:
                r.add("error", "egress_without_resource",
                      "http_egress needs a 'resource' host or URL fragment to match", path)


def _check_steps(s: Scenario, r: ValidationReport) -> None:
    steps = s.spec.attack.steps
    kinds = {st.kind for st in steps}

    if not (kinds & {"agent_message", "tool_response_injection"}):
        r.add(
            "warning",
            "no_stimulus",
            "no step actually drives the agent (agent_message or "
            "tool_response_injection). The run will collect evidence of nothing.",
            "spec/attack/steps",
        )

    for i, st in enumerate(steps):
        if st.kind == "wait" and st.seconds is None:
            r.add("error", "wait_without_seconds", f"step '{st.id}' is a wait with no seconds",
                  f"spec/attack/steps/{i}")
        if st.kind == "agent_message" and st.payload is None and st.payload_ref is None:
            r.add("error", "message_without_payload",
                  f"step '{st.id}' sends a message with no payload", f"spec/attack/steps/{i}")
        if st.kind == "assume_identity" and not st.as_principal:
            r.add("error", "identity_without_principal",
                  f"step '{st.id}' assumes an identity but names no principal",
                  f"spec/attack/steps/{i}")

    principals = {st.as_principal for st in steps if st.as_principal}
    if "multi_tenant" in s.spec.target.capabilities and len(principals) < 2:
        r.add(
            "warning",
            "single_principal_tenancy_test",
            "a multi-tenant scenario that only ever acts as one principal cannot "
            "demonstrate a cross-tenant boundary failure.",
            "spec/attack/steps",
        )


def _check_risk_coherence(s: Scenario, r: ValidationReport) -> None:
    risk = s.spec.risk
    sensitive = {"pii", "secret"} & set(risk.data_classes_touched)
    if sensitive and not risk.requires_approval:
        r.add(
            "error",
            "sensitive_data_without_approval",
            f"scenario touches {sorted(sensitive)} but does not require approval",
            "spec/risk",
        )
    regression = s.spec.regression
    if risk.destructive and regression.gate == "blocking" and "pr" in regression.ci_profiles:
        r.add(
            "warning",
            "destructive_in_pr_gate",
            "a destructive scenario as a blocking PR gate will wedge the merge "
            "queue the first time cleanup fails. Prefer the nightly profile.",
            "spec/regression",
        )


def _check_references(s: Scenario, r: ValidationReport) -> None:
    refs = s.metadata.references
    if not (refs.owasp_agentic or refs.owasp_llm or refs.mitre_attack or refs.mitre_atlas):
        r.add(
            "info",
            "unmapped_scenario",
            "no OWASP/MITRE mapping, so this scenario will not appear in coverage "
            "reporting.",
            "metadata/references",
        )


def _check_applicability(s: Scenario, t: Target, r: ValidationReport) -> None:
    """Would this scenario even be allowed to run against this target?

    Reported as validation issues rather than raised, so an author can see every
    mismatch at once instead of fixing them one exception at a time.
    """
    if t.environment not in s.spec.target.environments:
        r.add("error", "environment_mismatch",
              f"target '{t.id}' is {t.environment}; scenario allows "
              f"{s.spec.target.environments}", "spec/target/environments")

    missing = set(s.spec.target.capabilities) - set(t.capabilities)
    if missing:
        r.add("error", "missing_capabilities",
              f"target '{t.id}' does not declare {sorted(missing)}", "spec/target/capabilities")

    if s.spec.target.target_ids and t.id not in s.spec.target.target_ids:
        r.add("error", "target_not_pinned",
              f"scenario is pinned to {s.spec.target.target_ids}", "spec/target/target_ids")

    if s.spec.attack.executor not in t.allowed_executors:
        r.add("error", "executor_not_allowed",
              f"target '{t.id}' allows {t.allowed_executors}, scenario needs "
              f"'{s.spec.attack.executor}'", "spec/attack/executor")

    from agentsec.models.scenario import RISK_ORDER

    if RISK_ORDER[s.spec.risk.level] > RISK_ORDER[t.max_risk_level]:
        r.add("error", "risk_exceeds_target",
              f"scenario risk '{s.spec.risk.level}' exceeds target max "
              f"'{t.max_risk_level}'", "spec/risk/level")

    if s.spec.risk.destructive and not t.allow_destructive:
        r.add("error", "destructive_not_allowed",
              f"target '{t.id}' does not permit destructive scenarios", "spec/risk/destructive")

    # An assertion with no backend behind it is the quietest failure mode there
    # is: the axis silently degrades and the dashboard shows a gap that is really
    # a plumbing problem.
    # Both detection backends are checked, not only Wazuh: a scenario that
    # detects purely on spans has the identical plumbing dependency, and
    # HarnessService.validate_detection already reports both.
    contract = s.spec.contract
    if contract.detection:
        for backend_name, label in (("wazuh", "Wazuh"), ("otel", "OTel")):
            if getattr(contract.detection, backend_name) is None:
                continue
            backend = getattr(t.evidence, backend_name)
            if backend is None or backend.kind == "none":
                r.add("error", "detection_backend_missing",
                      f"scenario asserts {label} detection but target '{t.id}' has no "
                      f"{label} evidence backend configured",
                      f"spec/contract/detection/{backend_name}")
    if contract.evidence:
        for axis_name, backend_name in (
            ("otel", "otel"), ("tool_audit", "tool_audit"), ("state_diff", "state_diff")
        ):
            if getattr(contract.evidence, axis_name) is None:
                continue
            backend = getattr(t.evidence, backend_name)
            if backend is None or backend.kind == "none":
                r.add("error", "evidence_backend_missing",
                      f"scenario asserts {axis_name} evidence but target '{t.id}' has no "
                      f"{backend_name} backend configured",
                      f"spec/contract/evidence/{axis_name}")


def validate_scenario_path(path: Path, target: Target | None = None) -> ValidationReport:
    from agentsec.scenario.loader import load_scenario_dict

    raw = load_scenario_dict(path)
    schema_report = validate_scenario_dict(raw)
    if not schema_report.ok:
        return schema_report

    from agentsec.scenario.loader import load_scenario_file

    return validate_scenario(load_scenario_file(path), target=target, raw=raw)
