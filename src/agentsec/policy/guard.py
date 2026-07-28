"""The policy guard: the one place that decides whether a run may start.

Everything upstream — CLI, MCP gateway, CI — funnels through ``PolicyGuard.check``.
Putting the decision anywhere else means growing a second, subtly different copy
of it later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from agentsec.models.scenario import RISK_ORDER, RiskLevel, Scenario
from agentsec.models.target import Target
from agentsec.policy.approvals import ApprovalStore
from agentsec.policy.profiles import Profile


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    approval_id: str | None = None
    requires_approval: bool = False

    @property
    def summary(self) -> str:
        if self.allowed:
            return "allowed"
        return "; ".join(self.reasons) or "refused"

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "requires_approval": self.requires_approval,
            "approval_id": self.approval_id,
            "reasons": list(self.reasons),
        }


class PolicyGuard:
    def __init__(self, approvals: ApprovalStore | None = None) -> None:
        self._approvals = approvals

    def check(
        self,
        *,
        scenario: Scenario,
        target: Target,
        profile: Profile,
        approval_id: str | None = None,
        now: datetime | None = None,
    ) -> PolicyDecision:
        now = now or datetime.now(UTC)
        reasons: list[str] = []
        risk = scenario.spec.risk

        # --- environment -------------------------------------------------
        # Belt and braces: the type system already excludes production, but if a
        # future schema change ever adds it, this refuses rather than runs.
        if str(target.environment) == "production":
            reasons.append("target environment is production; refused unconditionally")
        if target.environment not in scenario.spec.target.environments:
            reasons.append(
                f"target environment '{target.environment}' is not in the scenario's "
                f"allowed environments {scenario.spec.target.environments}"
            )

        # --- capability and executor fit ---------------------------------
        missing = set(scenario.spec.target.capabilities) - set(target.capabilities)
        if missing:
            reasons.append(f"target lacks required capabilities: {sorted(missing)}")
        if scenario.spec.target.target_ids and target.id not in scenario.spec.target.target_ids:
            reasons.append(f"scenario is pinned to targets {scenario.spec.target.target_ids}")
        if scenario.spec.attack.executor not in target.allowed_executors:
            reasons.append(
                f"executor '{scenario.spec.attack.executor}' is not permitted for this "
                f"target (allowed: {target.allowed_executors})"
            )

        # --- risk ceiling: the stricter of target and profile wins --------
        ceiling = min(
            RISK_ORDER[target.max_risk_level],
            RISK_ORDER[RiskLevel(profile.max_risk_level)],
        )
        if RISK_ORDER[risk.level] > ceiling:
            reasons.append(
                f"scenario risk '{risk.level}' exceeds the effective ceiling "
                f"(target '{target.max_risk_level}', profile '{profile.max_risk_level}')"
            )

        if risk.destructive:
            if not target.allow_destructive:
                reasons.append(f"target '{target.id}' does not permit destructive scenarios")
            if not profile.allow_destructive:
                reasons.append(f"profile '{profile.name}' does not permit destructive scenarios")

        # --- quarantine expiry -------------------------------------------
        quarantined_until = scenario.spec.regression.quarantined_until
        if quarantined_until:
            try:
                until = datetime.fromisoformat(quarantined_until).replace(tzinfo=UTC)
                if until > now:
                    reasons.append(
                        f"scenario is quarantined until {quarantined_until}"
                    )
            except ValueError:
                reasons.append(
                    f"scenario has an unparseable quarantined_until: {quarantined_until!r}"
                )

        # --- approval -----------------------------------------------------
        requires_approval = bool(risk.requires_approval or risk.destructive)
        used_approval: str | None = None
        if requires_approval:
            if not approval_id:
                reasons.append(
                    "scenario requires an approval token; grant one with "
                    "`agentsec approve` and pass --approval"
                )
            elif self._approvals is None:
                reasons.append("approval supplied but no approval store is configured")
            else:
                approval = self._approvals.get(approval_id)
                if approval is None:
                    reasons.append(f"unknown approval '{approval_id}'")
                elif not approval.is_valid_for(scenario.id, target.id, now=now):
                    reasons.append(approval.invalid_reason(scenario.id, target.id, now=now))
                else:
                    used_approval = approval_id

        return PolicyDecision(
            allowed=not reasons,
            reasons=reasons,
            approval_id=used_approval,
            requires_approval=requires_approval,
        )
