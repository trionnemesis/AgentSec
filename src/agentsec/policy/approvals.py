"""Approval tokens for high-risk runs.

Approvals are scoped (scenario + target), time-bounded, and single-use. The
gateway never mints one: an approval must be created out-of-band by a human, so
that a compromised or over-eager model cannot approve its own request.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from agentsec.errors import ConfigError


class Approval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str
    scenario_id: str
    target_id: str
    approved_by: str
    expires_at: datetime
    reason: str = ""
    consumed_at: datetime | None = None
    consumed_by_run: str | None = None

    def is_valid_for(
        self, scenario_id: str, target_id: str, *, now: datetime | None = None
    ) -> bool:
        now = now or datetime.now(UTC)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        return (
            self.consumed_at is None
            and expires > now
            and self.scenario_id in (scenario_id, "*")
            and self.target_id in (target_id, "*")
        )

    def invalid_reason(
        self, scenario_id: str, target_id: str, *, now: datetime | None = None
    ) -> str:
        now = now or datetime.now(UTC)
        expires = (
            self.expires_at if self.expires_at.tzinfo
            else self.expires_at.replace(tzinfo=UTC)
        )
        if self.consumed_at is not None:
            return f"approval already consumed by run {self.consumed_by_run}"
        if expires <= now:
            return f"approval expired at {expires.isoformat()}"
        if self.scenario_id not in (scenario_id, "*"):
            return f"approval is scoped to scenario {self.scenario_id}"
        if self.target_id not in (target_id, "*"):
            return f"approval is scoped to target {self.target_id}"
        return "approval is valid"


class ApprovalFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    apiVersion: str = "agentsec.dev/v1"
    kind: str = "ApprovalLedger"
    approvals: list[Approval] = Field(default_factory=list)


class ApprovalStore:
    """File-backed approval ledger.

    A YAML file is the right primitive for the local-first MVP: it is
    reviewable, diffable and can be committed. A team deployment should swap
    this for the company's change-management system behind the same interface.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    def _read(self) -> ApprovalFile:
        if not self.path.is_file():
            return ApprovalFile()
        try:
            data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{self.path.name}: invalid YAML: {exc}") from exc
        try:
            return ApprovalFile.model_validate(data)
        except Exception as exc:
            raise ConfigError(f"{self.path.name}: {exc}") from exc

    def _write(self, ledger: ApprovalFile) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            yaml.safe_dump(ledger.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )

    def list(self) -> list[Approval]:
        return self._read().approvals

    def get(self, approval_id: str) -> Approval | None:
        for a in self._read().approvals:
            if a.approval_id == approval_id:
                return a
        return None

    def grant(
        self,
        *,
        scenario_id: str,
        target_id: str,
        approved_by: str,
        ttl_minutes: int = 60,
        reason: str = "",
    ) -> Approval:
        approval = Approval(
            approval_id="apr_" + secrets.token_hex(8),
            scenario_id=scenario_id,
            target_id=target_id,
            approved_by=approved_by,
            expires_at=datetime.now(UTC) + timedelta(minutes=ttl_minutes),
            reason=reason,
        )
        ledger = self._read()
        ledger.approvals.append(approval)
        self._write(ledger)
        return approval

    def consume(self, approval_id: str, run_id: str) -> None:
        ledger = self._read()
        for a in ledger.approvals:
            if a.approval_id == approval_id and a.consumed_at is None:
                a.consumed_at = datetime.now(UTC)
                a.consumed_by_run = run_id
                self._write(ledger)
                return
