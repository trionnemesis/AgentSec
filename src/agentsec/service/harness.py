"""Harness application service — the internal API.

This is the seam the whole architecture rests on. The MCP gateway, the CLI and
CI all call *this*, and none of them reach past it into executors, collectors or
the database. Consequences worth stating plainly:

* Dropping Claude entirely costs nothing: the CLI already exercises every path.
* The gateway cannot grow behaviour the CLI does not have, so there is never a
  "Claude-only" code path that escapes review.
* Long-running work stays out of the MCP process; the gateway starts a run and
  polls, it does not host it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentsec.config import Settings, load_settings
from agentsec.errors import (
    AgentSecError,
    InvalidTransition,
    PolicyViolation,
    ScenarioError,
    TargetNotFound,
)
from agentsec.evaluation.evaluator import PurpleEvaluator
from agentsec.evidence.collector import EvidenceCollector
from agentsec.execution.base import ExecutionContext
from agentsec.execution.registry import available_executors, get_executor
from agentsec.models.evidence import Evidence
from agentsec.models.finding import FINDING_TRANSITIONS, Finding, FindingStatus
from agentsec.models.run import Run, RunStatus
from agentsec.models.scenario import Scenario
from agentsec.models.target import Target
from agentsec.policy.allowlist import load_allowlist
from agentsec.policy.approvals import ApprovalStore
from agentsec.policy.guard import PolicyGuard
from agentsec.policy.profiles import Profile, load_profiles
from agentsec.reporting.html import write_html_report
from agentsec.reporting.junit import render_junit
from agentsec.reporting.normalizer import (
    RunSummary,
    latest_per_scenario,
    normalize_batch,
    normalize_run,
)
from agentsec.scenario.catalog import ScenarioCatalog
from agentsec.scenario.loader import scenario_digest
from agentsec.scenario.validator import validate_scenario


@dataclass
class BatchResult:
    runs: list[Run]
    summaries: list[RunSummary]
    report: dict[str, Any]

    @property
    def exit_code(self) -> int:
        return int(self.report.get("exit_code", 0))


class HarnessService:
    def __init__(self, settings: Settings | None = None, *, actor: str | None = None) -> None:
        self.settings = settings or load_settings()
        self.settings.ensure_dirs()
        self.actor = actor or self.settings.actor

        from agentsec.store.sqlite import ResultStore

        self.store = ResultStore(self.settings.db_path)
        self.approvals = ApprovalStore(self.settings.approvals_file)
        self.guard = PolicyGuard(self.approvals)
        self.evaluator = PurpleEvaluator(self.settings.workspace)
        self.collector = EvidenceCollector(self.settings.workspace)

        self._catalog: ScenarioCatalog | None = None
        self._allowlist = None
        self._profiles = None

    # -- lazily loaded configuration ---------------------------------------

    @property
    def catalog(self) -> ScenarioCatalog:
        if self._catalog is None:
            self._catalog = ScenarioCatalog.from_dir(self.settings.scenarios_dir)
        return self._catalog

    @property
    def profiles(self):  # noqa: ANN201 - ProfileSet, avoids a circular import in typing
        if self._profiles is None:
            self._profiles = load_profiles(self.settings.profiles_file)
        return self._profiles

    def _targets(self):  # noqa: ANN202
        if self._allowlist is None:
            self._allowlist = load_allowlist(self.settings.targets_file)
        return self._allowlist

    def get_target(self, target_id: str) -> Target:
        target = self._targets().get(target_id)
        if target is None:
            raise TargetNotFound(
                f"unknown target '{target_id}'",
                details={"known": [t.id for t in self._targets().targets]},
            )
        return target

    # -- read operations ----------------------------------------------------

    def list_targets(self) -> list[dict[str, Any]]:
        return [t.redacted() for t in self._targets().targets]

    def get_target_schema(self, target_id: str) -> dict[str, Any]:
        """What a scenario author needs to know to write against this target."""
        target = self.get_target(target_id)
        return {
            **target.redacted(),
            "executors": available_executors(target, self.settings.workspace),
            "applicable_scenarios": [
                s.id for s in self.catalog.select(target=target)
            ],
            "profiles": self.profiles.names(),
        }

    def list_scenarios(self, *, target_id: str | None = None) -> list[dict[str, Any]]:
        target = self.get_target(target_id) if target_id else None
        scenarios = (
            self.catalog.select(target=target) if target
            else [e.scenario for e in self.catalog]
        )
        return [
            {
                "id": s.id,
                "title": s.metadata.title,
                "severity": str(s.metadata.severity),
                "tags": list(s.metadata.tags),
                "owasp_agentic": list(s.metadata.references.owasp_agentic),
                "executor": s.spec.attack.executor,
                "risk_level": str(s.spec.risk.level),
                "requires_approval": s.spec.risk.requires_approval,
                "tested_axes": s.tested_axes,
                "ci_profiles": list(s.spec.regression.ci_profiles),
                "gate": s.spec.regression.gate,
            }
            for s in sorted(scenarios, key=lambda s: s.id)
        ]

    def coverage(self) -> dict[str, Any]:
        cov = self.catalog.coverage()
        cov["verdict_counts"] = self.store.verdict_counts()
        cov["load_errors"] = self.catalog.load_errors
        return cov

    def get_run(self, run_id: str) -> Run:
        return self.store.get_run(run_id)

    def get_run_evidence(self, run_id: str) -> dict[str, Any]:
        run = self.store.get_run(run_id)
        if not run.evidence_ref:
            raise AgentSecError(f"run '{run_id}' has no stored evidence")
        path = Path(run.evidence_ref)
        if not path.is_absolute():
            path = self.settings.workspace / path
        if not path.is_file():
            raise AgentSecError(f"evidence bundle missing on disk: {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    def list_runs(self, **kwargs: Any) -> list[Run]:
        return self.store.list_runs(**kwargs)

    # -- validation ---------------------------------------------------------

    def validate_scenario(
        self,
        *,
        scenario_id: str | None = None,
        scenario_body: dict[str, Any] | None = None,
        target_id: str | None = None,
    ) -> dict[str, Any]:
        """Validate a catalogued scenario or an inline draft.

        Inline drafts are how Claude Code proposes a new scenario without being
        able to write to the workspace: the model authors YAML, the service
        judges it, and a human is still the one who commits the file.
        """
        if (scenario_id is None) == (scenario_body is None):
            raise ScenarioError("provide exactly one of scenario_id or scenario_body")

        target = self.get_target(target_id) if target_id else None

        if scenario_id is not None:
            scenario = self.catalog.get(scenario_id)
            report = validate_scenario(scenario, target=target)
        else:
            from agentsec.scenario.validator import validate_scenario_dict

            assert scenario_body is not None
            schema_report = validate_scenario_dict(scenario_body)
            if not schema_report.ok:
                report = schema_report
            else:
                scenario = Scenario.model_validate(scenario_body)
                report = validate_scenario(scenario, target=target, raw=scenario_body)

        self.store.audit(
            actor=self.actor,
            action="validate_scenario",
            subject=report.scenario_id,
            outcome="valid" if report.ok else "invalid",
            detail={"target_id": target_id, "errors": len(report.errors)},
        )
        return report.to_dict()

    def preview_run(
        self,
        *,
        target_id: str,
        scenario_ids: list[str] | None = None,
        profile: str = "pr",
    ) -> dict[str, Any]:
        """Everything that would happen, with nothing happening.

        The point is that a caller — human or model — can see the policy decision
        and the evidence plan *before* consenting to execution.
        """
        target = self.get_target(target_id)
        prof = self.profiles.get(profile)
        selected = self.catalog.select(
            profile=profile if not scenario_ids else None,
            target=target,
            scenario_ids=scenario_ids,
        )

        plan: list[dict[str, Any]] = []
        for scenario in selected:
            decision = self.guard.check(scenario=scenario, target=target, profile=prof)
            validation = validate_scenario(scenario, target=target)
            plan.append(
                {
                    "scenario_id": scenario.id,
                    "title": scenario.metadata.title,
                    "executor": scenario.spec.attack.executor,
                    "risk_level": str(scenario.spec.risk.level),
                    "destructive": scenario.spec.risk.destructive,
                    "steps": [
                        {"id": s.id, "kind": s.kind, "as_principal": s.as_principal}
                        for s in scenario.spec.attack.steps
                    ],
                    "tested_axes": scenario.tested_axes,
                    "evidence_sources": sorted(
                        EvidenceCollector.required_sources(scenario)
                    ),
                    "policy": decision.to_dict(),
                    "validation": {
                        "valid": validation.ok,
                        "errors": [i.render() for i in validation.errors],
                        "warnings": [i.render() for i in validation.warnings],
                    },
                    "gate": scenario.spec.regression.gate,
                    "would_block_on_failure": scenario.spec.regression.gate == "blocking",
                }
            )

        blocked = [p for p in plan if not p["policy"]["allowed"]]
        self.store.audit(
            actor=self.actor, action="preview_run", subject=target_id, outcome="ok",
            detail={"profile": profile, "scenarios": len(plan), "blocked": len(blocked)},
        )

        return {
            "target": target.redacted(),
            "profile": profile,
            "scenario_count": len(plan),
            "runnable_count": len(plan) - len(blocked),
            "blocked_count": len(blocked),
            "requires_approval": [
                p["scenario_id"] for p in plan if p["policy"]["requires_approval"]
            ],
            "plan": plan,
        }

    # -- execution ----------------------------------------------------------

    def start_run(
        self,
        *,
        target_id: str,
        scenario_ids: list[str] | None = None,
        profile: str = "pr",
        dry_run: bool = False,
        approval_id: str | None = None,
    ) -> BatchResult:
        target = self.get_target(target_id)
        prof = self.profiles.get(profile)
        selected = self.catalog.select(
            profile=profile if not scenario_ids else None,
            target=target,
            scenario_ids=scenario_ids,
        )

        if not selected:
            raise PolicyViolation(
                f"no scenarios selected for target '{target_id}' with profile '{profile}'",
                details={
                    "catalog_size": len(self.catalog),
                    "load_errors": self.catalog.load_errors,
                },
            )

        runs: list[Run] = []
        summaries: list[RunSummary] = []

        for scenario in selected:
            run = self._run_one(
                scenario=scenario,
                target=target,
                profile=prof,
                dry_run=dry_run,
                approval_id=approval_id,
            )
            runs.append(run)
            collector_errors = self._collector_errors_for(run)
            summaries.append(normalize_run(run, scenario, prof, collector_errors))

        report = normalize_batch(summaries, profile=profile, target_id=target_id)
        return BatchResult(runs=runs, summaries=summaries, report=report)

    def _run_one(
        self,
        *,
        scenario: Scenario,
        target: Target,
        profile: Profile,
        dry_run: bool,
        approval_id: str | None,
    ) -> Run:
        run_id = self._next_run_id()
        created = datetime.now(UTC)
        digest = scenario_digest(scenario)

        decision = self.guard.check(
            scenario=scenario, target=target, profile=profile, approval_id=approval_id
        )

        if not decision.allowed:
            run = Run(
                run_id=run_id, scenario_id=scenario.id, target_id=target.id,
                profile=profile.name, status=RunStatus.REFUSED, created_at=created,
                finished_at=datetime.now(UTC), dry_run=dry_run,
                refusal_reason=decision.summary, initiated_by=self.actor,
                scenario_digest=digest,
            )
            self.store.save_run(run)
            self.store.audit(
                actor=self.actor, action="start_run", subject=scenario.id, outcome="refused",
                detail={"target_id": target.id, "reasons": decision.reasons, "run_id": run_id},
            )
            return run

        if dry_run:
            run = Run(
                run_id=run_id, scenario_id=scenario.id, target_id=target.id,
                profile=profile.name, status=RunStatus.COMPLETED, created_at=created,
                started_at=created, finished_at=datetime.now(UTC), dry_run=True,
                refusal_reason="dry run: policy allowed, nothing executed",
                initiated_by=self.actor, scenario_digest=digest,
                approval_id=decision.approval_id,
            )
            self.store.save_run(run)
            self.store.audit(
                actor=self.actor, action="start_run", subject=scenario.id, outcome="dry_run",
                detail={"target_id": target.id, "run_id": run_id},
            )
            return run

        if decision.approval_id:
            # Consumed before execution: an approval must not survive a crash
            # mid-run and be reusable for a second attempt.
            self.approvals.consume(decision.approval_id, run_id)

        started = datetime.now(UTC)
        executor = get_executor(scenario.spec.attack.executor, self.settings.workspace)
        ok, reason = executor.available(target)

        if not ok:
            verdict = self.evaluator.execution_failure_verdict(reason)
            run = Run(
                run_id=run_id, scenario_id=scenario.id, target_id=target.id,
                profile=profile.name, status=RunStatus.FAILED, created_at=created,
                started_at=started, finished_at=datetime.now(UTC), verdict=verdict,
                refusal_reason=reason, initiated_by=self.actor, scenario_digest=digest,
                approval_id=decision.approval_id,
            )
            self.store.save_run(run)
            self.store.audit(
                actor=self.actor, action="start_run", subject=scenario.id,
                outcome="executor_unavailable",
                detail={"target_id": target.id, "reason": reason, "run_id": run_id},
            )
            return run

        ctx = ExecutionContext(
            run_id=run_id,
            scenario=scenario,
            scenario_path=self._scenario_path(scenario.id),
            target=target,
            raw_dir=self.settings.raw_dir,
            timeout_seconds=min(scenario.spec.attack.timeout_seconds, profile.max_duration_seconds),
        )

        try:
            execution, transcript = executor.execute(ctx)
        except AgentSecError as exc:
            crash: str | None = exc.message
        except Exception as exc:
            # An executor bug must lose the run, not the whole batch.
            crash = f"{type(exc).__name__}: {exc}"
        else:
            crash = None

        if crash is not None:
            verdict = self.evaluator.execution_failure_verdict(crash)
            run = Run(
                run_id=run_id, scenario_id=scenario.id, target_id=target.id,
                profile=profile.name, status=RunStatus.FAILED, created_at=created,
                started_at=started, finished_at=datetime.now(UTC), verdict=verdict,
                refusal_reason=crash, initiated_by=self.actor, scenario_digest=digest,
                approval_id=decision.approval_id,
            )
            self.store.save_run(run)
            self.store.audit(
                actor=self.actor, action="start_run", subject=scenario.id, outcome="error",
                detail={"target_id": target.id, "error": crash, "run_id": run_id},
            )
            return run

        failure = None if execution.ok else (execution.error or "attack execution failed")

        evidence = self.collector.collect(
            run_id=run_id,
            scenario=scenario,
            target=target,
            transcript=transcript,
            window_start=started,
        )
        evidence_ref = self._persist_evidence(evidence)

        # An attack that could not complete cannot produce a meaningful verdict:
        # asserting "no alert fired" against a run that never reached the trigger
        # step would manufacture a detection gap out of a plumbing failure.
        verdict = (
            self.evaluator.evaluate(scenario, evidence)
            if execution.ok
            else self.evaluator.execution_failure_verdict(failure or "attack execution failed")
        )

        run = Run(
            run_id=run_id, scenario_id=scenario.id, target_id=target.id,
            profile=profile.name,
            status=RunStatus.COMPLETED if execution.ok else RunStatus.FAILED,
            created_at=created, started_at=started, finished_at=datetime.now(UTC),
            execution=execution, verdict=verdict, evidence_ref=evidence_ref,
            initiated_by=self.actor, scenario_digest=digest,
            approval_id=decision.approval_id,
        )
        self.store.save_run(run)
        self.store.audit(
            actor=self.actor, action="start_run", subject=scenario.id,
            outcome=str(verdict.purple_verdict),
            detail={"target_id": target.id, "run_id": run_id},
        )

        if not verdict.is_secure:
            self._upsert_finding(run, scenario)

        return run

    # -- findings -----------------------------------------------------------

    def _upsert_finding(self, run: Run, scenario: Scenario) -> Finding:
        """Create or refresh the finding for a non-secure run.

        Repeated failures update one finding rather than accumulating a new one
        per nightly run — otherwise the backlog measures how often CI runs, not
        how many problems exist.
        """
        assert run.verdict is not None
        now = datetime.now(UTC)
        existing = self.store.find_open_finding(run.scenario_id, run.target_id)

        failed_axes: list[str] = [
            str(a.axis) for a in run.verdict.axes if a.status.value in {"fail", "error"}
        ]
        failed_checks = [
            f"[{c.axis}] {c.assertion} -> {c.observed}"
            for a in run.verdict.axes
            for c in a.failed_checks
        ]

        if existing:
            existing.last_seen_run = run.run_id
            existing.updated_at = now
            existing.verdict = run.verdict.purple_verdict
            existing.failed_axes = failed_axes
            existing.failed_checks = failed_checks
            self.store.save_finding(existing)
            return existing

        finding = Finding(
            finding_id=f"FND-{run.run_id.removeprefix('RUN-')}",
            scenario_id=run.scenario_id,
            target_id=run.target_id,
            title=f"{scenario.metadata.title} ({run.verdict.purple_verdict})",
            severity=scenario.metadata.severity,
            verdict=run.verdict.purple_verdict,
            first_seen_run=run.run_id,
            last_seen_run=run.run_id,
            created_at=now,
            updated_at=now,
            failed_axes=failed_axes,
            failed_checks=failed_checks,
        )
        self.store.save_finding(finding)
        self.store.audit(
            actor=self.actor, action="create_finding", subject=finding.finding_id,
            outcome=str(finding.verdict), detail={"run_id": run.run_id},
        )
        return finding

    def promote_finding(
        self,
        *,
        finding_id: str,
        status: str,
        regression_test_ref: str | None = None,
        detection_rule_ref: str | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        finding = self.store.get_finding(finding_id)
        target_status = FindingStatus(status)

        if not finding.can_transition_to(target_status):
            raise InvalidTransition(
                f"cannot move finding from '{finding.status}' to '{target_status}'",
                details={
                    "allowed": sorted(
                        str(s) for s in FINDING_TRANSITIONS.get(finding.status, set())
                    )
                },
            )

        if regression_test_ref:
            finding.regression_test_ref = regression_test_ref
        if detection_rule_ref:
            finding.detection_rule_ref = detection_rule_ref

        if target_status is FindingStatus.VERIFIED:
            blockers = finding.blocking_reasons_for_verified()
            if blockers:
                raise InvalidTransition(
                    "finding cannot be verified yet: " + "; ".join(blockers),
                    details={"blockers": blockers},
                )

        finding.status = target_status
        finding.updated_at = datetime.now(UTC)
        if note:
            finding.notes = note
        self.store.save_finding(finding)
        self.store.audit(
            actor=self.actor, action="promote_finding", subject=finding_id,
            outcome=str(target_status), detail={"note": note},
        )
        return finding.model_dump(mode="json")

    def list_findings(self, *, status: str | None = None) -> list[dict[str, Any]]:
        findings = self.store.list_findings(
            status=FindingStatus(status) if status else None
        )
        return [f.model_dump(mode="json") for f in findings]

    def create_regression_draft(self, *, finding_id: str) -> dict[str, Any]:
        """Emit a scenario YAML draft pinned to the exact failure.

        Returned as text, not written to disk. A regression test entering the
        catalogue is a code review event, not a side effect of an API call.
        """
        import yaml

        finding = self.store.get_finding(finding_id)
        source = self.catalog.get(finding.scenario_id)

        draft = source.model_dump(mode="json", exclude_none=True)
        suffix = finding.finding_id.split("-")[-1][:3].upper() or "R01"
        base_id = source.id.rsplit("-", 1)[0]
        draft["metadata"]["id"] = f"{base_id}-9{suffix[:2]}"
        draft["metadata"]["title"] = f"Regression: {source.metadata.title}"[:160]
        draft["metadata"].setdefault("tags", []).append("regression")
        draft["spec"]["regression"] = {
            "ci_profiles": ["pr", "nightly"],
            "gate": "blocking",
            "linked_finding": finding.finding_id,
        }

        self.store.audit(
            actor=self.actor, action="create_regression_draft", subject=finding_id,
            outcome="drafted", detail={"source_scenario": source.id},
        )

        return {
            "finding_id": finding.finding_id,
            "source_scenario_id": source.id,
            "draft_scenario_id": draft["metadata"]["id"],
            "suggested_path": f"scenarios/{draft['metadata']['id']}.yaml",
            "yaml": yaml.safe_dump(draft, sort_keys=False, allow_unicode=True),
            "next_steps": [
                "review the draft, commit it under scenarios/",
                "run `agentsec run --scenario <id>` to confirm it reproduces the failure",
                "link it back with `agentsec finding promote --regression <path>`",
            ],
        }

    # -- comparison and reporting -------------------------------------------

    def compare_runs(self, *, run_a: str, run_b: str) -> dict[str, Any]:
        a, b = self.store.get_run(run_a), self.store.get_run(run_b)

        def axes(run: Run) -> dict[str, str]:
            v = run.verdict
            return {
                axis: str(getattr(v, axis)) if v else "error"
                for axis in ("prevention", "detection", "evidence", "response")
            }

        axes_a, axes_b = axes(a), axes(b)
        changed = {k: [axes_a[k], axes_b[k]] for k in axes_a if axes_a[k] != axes_b[k]}

        va = str(a.verdict.purple_verdict) if a.verdict else "error"
        vb = str(b.verdict.purple_verdict) if b.verdict else "error"

        checks_a = _check_map(a)
        checks_b = _check_map(b)
        regressed = sorted(
            k for k in checks_b
            if checks_b[k] == "fail" and checks_a.get(k) == "pass"
        )
        fixed = sorted(
            k for k in checks_a
            if checks_a[k] == "fail" and checks_b.get(k) == "pass"
        )

        return {
            "run_a": {"run_id": a.run_id, "verdict": va, "axes": axes_a,
                      "scenario_digest": a.scenario_digest},
            "run_b": {"run_id": b.run_id, "verdict": vb, "axes": axes_b,
                      "scenario_digest": b.scenario_digest},
            "same_scenario": a.scenario_id == b.scenario_id,
            # A changed digest means the contract itself moved, so a verdict
            # difference may say nothing about the system under test.
            "contract_changed": a.scenario_digest != b.scenario_digest,
            "verdict_changed": va != vb,
            "axes_changed": changed,
            "regressed_checks": regressed,
            "fixed_checks": fixed,
        }

    def generate_report(
        self,
        *,
        target_id: str | None = None,
        profile: str | None = None,
        limit: int = 50,
        formats: list[str] | None = None,
    ) -> dict[str, Any]:
        """Render stored runs. Omit ``profile`` to report across every profile.

        ``profile`` filters the runs as well as labelling the report — a report
        headed "profile pr" that also counted nightly runs would be worse than one
        that says "all".
        """
        formats = formats or ["html", "json"]
        runs = self.store.list_runs(target_id=target_id, profile=profile, limit=limit)

        history = []
        for run in runs:
            scenario = None
            if run.scenario_id in self.catalog:
                scenario = self.catalog.get(run.scenario_id)
            prof = self.profiles.get(run.profile) if run.profile in self.profiles.profiles else None
            history.append(
                normalize_run(run, scenario, prof, self._collector_errors_for(run))
            )

        # The rollup answers "where does this target stand now", not "what has CI
        # done lately", so a scenario contributes its latest run and nothing else.
        summaries = latest_per_scenario(history)

        batch = normalize_batch(summaries, profile=profile or "all", target_id=target_id or "all")
        batch["superseded_runs"] = len(history) - len(summaries)
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        written: dict[str, str] = {}

        if "html" in formats:
            path = self.settings.reports_dir / f"report-{stamp}.html"
            write_html_report(path, batch, self.catalog.coverage())
            written["html"] = str(path)
        if "json" in formats:
            path = self.settings.reports_dir / f"report-{stamp}.json"
            path.write_text(json.dumps(batch, indent=2, default=str), encoding="utf-8")
            written["json"] = str(path)
        if "junit" in formats:
            path = self.settings.reports_dir / f"report-{stamp}.xml"
            path.write_text(render_junit(summaries), encoding="utf-8")
            written["junit"] = str(path)

        self.store.audit(
            actor=self.actor, action="generate_report", subject=target_id,
            outcome="ok", detail={"formats": formats, "runs": len(summaries)},
        )
        return {"written": written, "summary": {k: v for k, v in batch.items() if k != "runs"}}

    def validate_detection(
        self, *, scenario_id: str, target_id: str
    ) -> dict[str, Any]:
        """Check the detection side is wired up, without running an attack.

        Answers "is this contract even checkable here?" — the most common reason
        a detection gap turns out to be a config mistake rather than a real one.
        """
        scenario = self.catalog.get(scenario_id)
        target = self.get_target(target_id)
        contract = scenario.spec.contract.detection

        if contract is None or not (contract.wazuh or contract.otel):
            return {
                "scenario_id": scenario_id,
                "target_id": target_id,
                "checkable": False,
                "reason": "scenario asserts no detection expectations",
            }

        issues: list[str] = []
        expected_rules: list[str] = []

        if contract.wazuh:
            wazuh_backend = target.evidence.wazuh
            if wazuh_backend is None or wazuh_backend.kind == "none":
                issues.append("target has no Wazuh evidence backend configured")
            expected_rules = [
                a.rule_id for a in contract.wazuh.must_fire if a.rule_id
            ]
            if contract.wazuh.must_fire and not expected_rules:
                issues.append(
                    "must_fire assertions specify no rule_id, so a passing result "
                    "only proves *some* alert fired"
                )
        if contract.otel:
            otel_backend = target.evidence.otel
            if otel_backend is None or otel_backend.kind == "none":
                issues.append("target has no OTel evidence backend configured")

        latest = self.store.latest_run_for(scenario_id, target_id)

        return {
            "scenario_id": scenario_id,
            "target_id": target_id,
            "checkable": not issues,
            "issues": issues,
            "expected_wazuh_rules": expected_rules,
            "expected_spans": [
                a.name for a in (contract.otel.must_emit if contract.otel else [])
            ],
            "last_run": {
                "run_id": latest.run_id,
                "detection": str(latest.verdict.detection) if latest.verdict else None,
            } if latest else None,
        }

    # -- internals ----------------------------------------------------------

    def _scenario_path(self, scenario_id: str) -> Path | None:
        try:
            return self.catalog.path_of(scenario_id)
        except AgentSecError:
            return None

    def _persist_evidence(self, evidence: Evidence) -> str:
        path = self.settings.evidence_dir / f"{evidence.run_id}.json"
        path.write_text(evidence.model_dump_json(indent=2), encoding="utf-8")
        try:
            return str(path.relative_to(self.settings.workspace))
        except ValueError:
            return str(path)

    def _collector_errors_for(self, run: Run) -> list[dict[str, str]]:
        if not run.evidence_ref:
            return []
        try:
            bundle = self.get_run_evidence(run.run_id)
        except AgentSecError:
            return []
        return [
            {"source": e.get("source", ""), "message": e.get("message", "")}
            for e in bundle.get("collector_errors", [])
        ]

    def _next_run_id(self) -> str:
        """RUN-YYYYMMDD-NNN, sequential within the day."""
        today = datetime.now(UTC).strftime("%Y%m%d")
        prefix = f"RUN-{today}-"
        existing = [
            r.run_id for r in self.store.list_runs(limit=1000)
            if r.run_id.startswith(prefix)
        ]
        n = 0
        for rid in existing:
            try:
                n = max(n, int(rid.rsplit("-", 1)[1]))
            except (IndexError, ValueError):
                continue
        return f"{prefix}{n + 1:03d}"


def _check_map(run: Run) -> dict[str, str]:
    if run.verdict is None:
        return {}
    return {c.id: str(c.status) for a in run.verdict.axes for c in a.checks}
