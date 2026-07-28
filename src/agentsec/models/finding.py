"""Finding — a non-secure verdict promoted into tracked work.

The state machine is deliberately narrow. In particular a finding cannot reach
``verified`` without both a regression test and, for detection gaps, a detection
rule: closing a purple finding by fixing only the code leaves the blue side blind.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from agentsec.models.run import PurpleVerdict
from agentsec.models.scenario import Severity


class FindingStatus(StrEnum):
    NEW = "new"
    REPRODUCED = "reproduced"
    FIXING = "fixing"
    REGRESSION_ADDED = "regression_added"
    DETECTION_ADDED = "detection_added"
    VERIFIED = "verified"
    CLOSED = "closed"
    ACCEPTED_RISK = "accepted_risk"


#: Allowed transitions. Anything else is rejected by the service layer.
FINDING_TRANSITIONS: dict[FindingStatus, set[FindingStatus]] = {
    FindingStatus.NEW: {
        FindingStatus.REPRODUCED, FindingStatus.ACCEPTED_RISK, FindingStatus.CLOSED,
    },
    FindingStatus.REPRODUCED: {FindingStatus.FIXING, FindingStatus.ACCEPTED_RISK},
    FindingStatus.FIXING: {FindingStatus.REGRESSION_ADDED, FindingStatus.REPRODUCED},
    FindingStatus.REGRESSION_ADDED: {FindingStatus.DETECTION_ADDED, FindingStatus.VERIFIED},
    FindingStatus.DETECTION_ADDED: {FindingStatus.VERIFIED},
    FindingStatus.VERIFIED: {FindingStatus.CLOSED, FindingStatus.REPRODUCED},
    FindingStatus.CLOSED: {FindingStatus.REPRODUCED},
    FindingStatus.ACCEPTED_RISK: {FindingStatus.REPRODUCED, FindingStatus.CLOSED},
}


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    scenario_id: str
    target_id: str
    title: str
    severity: Severity
    verdict: PurpleVerdict
    status: FindingStatus = FindingStatus.NEW
    first_seen_run: str
    last_seen_run: str
    created_at: datetime
    updated_at: datetime
    failed_axes: list[str] = Field(default_factory=list)
    failed_checks: list[str] = Field(default_factory=list)
    regression_test_ref: str | None = None
    detection_rule_ref: str | None = None
    owner: str | None = None
    notes: str | None = None

    def can_transition_to(self, target: FindingStatus) -> bool:
        return target in FINDING_TRANSITIONS.get(self.status, set())

    def blocking_reasons_for_verified(self) -> list[str]:
        """Why this finding may not be marked verified yet."""
        reasons = []
        if not self.regression_test_ref:
            reasons.append("no regression test linked")
        if self.verdict is PurpleVerdict.DETECTION_GAP and not self.detection_rule_ref:
            reasons.append("detection gap with no detection rule linked")
        return reasons
