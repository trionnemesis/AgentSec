"""AgentSec CLI — the interface CI uses, and therefore the one that must never
depend on a model being present.

Exit codes are the contract:

  0  no blocking findings
  1  at least one blocking finding (a gate the profile declares fatal)
  2  usage, configuration or policy error — the run did not happen

The distinction between 1 and 2 matters in a pipeline: 1 means "your change broke
a control", 2 means "the harness could not tell you anything", and treating those
the same is how teams learn to ignore the job.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer

from agentsec.config import load_settings
from agentsec.errors import AgentSecError
from agentsec.reporting.junit import render_junit
from agentsec.service.harness import HarnessService

app = typer.Typer(
    name="agentsec",
    help="Purple-team harness for AI agents.",
    no_args_is_help=True,
    add_completion=False,
)
targets_app = typer.Typer(help="Inspect allowlisted targets.", no_args_is_help=True)
scenarios_app = typer.Typer(help="Inspect the scenario catalogue.", no_args_is_help=True)
finding_app = typer.Typer(help="Work with findings.", no_args_is_help=True)
app.add_typer(targets_app, name="targets")
app.add_typer(scenarios_app, name="scenarios")
app.add_typer(finding_app, name="finding")

EXIT_OK = 0
EXIT_BLOCKING = 1
EXIT_ERROR = 2

WorkspaceOpt = Annotated[
    Path | None,
    typer.Option("--workspace", "-w", help="Workspace root (default: $AGENTSEC_WORKSPACE or cwd)."),
]


def _service(workspace: Path | None) -> HarnessService:
    return HarnessService(load_settings(workspace))


def _echo_json(data: object) -> None:
    typer.echo(json.dumps(data, indent=2, default=str))


def _fail(exc: AgentSecError) -> None:
    typer.secho(f"error [{exc.code}]: {exc.message}", fg=typer.colors.RED, err=True)
    if exc.details:
        typer.secho(json.dumps(exc.details, indent=2, default=str), fg=typer.colors.YELLOW,
                    err=True)
    raise typer.Exit(EXIT_ERROR)


# --------------------------------------------------------------------------
# targets / scenarios
# --------------------------------------------------------------------------


@targets_app.command("list")
def targets_list(workspace: WorkspaceOpt = None) -> None:
    """List allowlisted targets."""
    try:
        _echo_json(_service(workspace).list_targets())
    except AgentSecError as exc:
        _fail(exc)


@targets_app.command("describe")
def targets_describe(target_id: str, workspace: WorkspaceOpt = None) -> None:
    """Show what a scenario author needs to know about one target."""
    try:
        _echo_json(_service(workspace).get_target_schema(target_id))
    except AgentSecError as exc:
        _fail(exc)


@scenarios_app.command("list")
def scenarios_list(
    target: Annotated[str | None, typer.Option("--target", "-t")] = None,
    workspace: WorkspaceOpt = None,
) -> None:
    """List scenarios, optionally filtered to those applicable to a target."""
    try:
        _echo_json(_service(workspace).list_scenarios(target_id=target))
    except AgentSecError as exc:
        _fail(exc)


@app.command()
def coverage(workspace: WorkspaceOpt = None) -> None:
    """Show OWASP Agentic Top 10 coverage and the latest verdict histogram."""
    try:
        _echo_json(_service(workspace).coverage())
    except AgentSecError as exc:
        _fail(exc)


# --------------------------------------------------------------------------
# validate / preview / run
# --------------------------------------------------------------------------


@app.command()
def validate(
    scenario: Annotated[str | None, typer.Option("--scenario", "-s")] = None,
    target: Annotated[str | None, typer.Option("--target", "-t")] = None,
    strict: Annotated[
        bool, typer.Option("--strict", help="Treat warnings as failures.")
    ] = False,
    workspace: WorkspaceOpt = None,
) -> None:
    """Validate one scenario, or the whole catalogue when --scenario is omitted."""
    try:
        service = _service(workspace)
        scenario_ids = [scenario] if scenario else service.catalog.ids()

        if not scenario_ids:
            typer.secho("no scenarios found", fg=typer.colors.YELLOW, err=True)
            raise typer.Exit(EXIT_ERROR)

        failed = 0
        for sid in scenario_ids:
            report = service.validate_scenario(scenario_id=sid, target_id=target)
            errors, warnings = report["error_count"], report["warning_count"]
            bad = errors > 0 or (strict and warnings > 0)
            failed += bool(bad)
            colour = typer.colors.RED if bad else (
                typer.colors.YELLOW if warnings else typer.colors.GREEN
            )
            typer.secho(f"{sid}: {errors} error(s), {warnings} warning(s)", fg=colour)
            for issue in report["issues"]:
                if issue["level"] == "info" and not strict:
                    continue
                typer.echo(f"    [{issue['level']}] {issue['code']}: {issue['message']}")

        if service.catalog.load_errors:
            typer.secho("\ncatalogue load errors:", fg=typer.colors.RED, err=True)
            for err in service.catalog.load_errors:
                typer.echo(f"    {err}", err=True)
            failed += len(service.catalog.load_errors)

        raise typer.Exit(EXIT_BLOCKING if failed else EXIT_OK)
    except AgentSecError as exc:
        _fail(exc)


@app.command()
def preview(
    target: Annotated[str, typer.Option("--target", "-t")],
    profile: Annotated[str, typer.Option("--profile", "-p")] = "pr",
    scenario: Annotated[list[str] | None, typer.Option("--scenario", "-s")] = None,
    workspace: WorkspaceOpt = None,
) -> None:
    """Show exactly what a run would do, without doing it."""
    try:
        _echo_json(
            _service(workspace).preview_run(
                target_id=target, scenario_ids=scenario or None, profile=profile
            )
        )
    except AgentSecError as exc:
        _fail(exc)


@app.command()
def run(
    target: Annotated[str, typer.Option("--target", "-t")],
    profile: Annotated[str, typer.Option("--profile", "-p")] = "pr",
    scenario: Annotated[list[str] | None, typer.Option("--scenario", "-s")] = None,
    output: Annotated[
        str, typer.Option("--output", "-o", help="text | json | junit")
    ] = "text",
    output_file: Annotated[Path | None, typer.Option("--output-file")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
    approval: Annotated[str | None, typer.Option("--approval")] = None,
    html: Annotated[
        bool, typer.Option("--html", help="Also write a self-contained HTML report.")
    ] = False,
    workspace: WorkspaceOpt = None,
) -> None:
    """Run scenarios against a target and exit non-zero on a blocking finding."""
    try:
        service = _service(workspace)
        result = service.start_run(
            target_id=target,
            scenario_ids=scenario or None,
            profile=profile,
            dry_run=dry_run,
            approval_id=approval,
        )

        if output == "json":
            payload = json.dumps(result.report, indent=2, default=str)
            _write(payload, output_file)
        elif output == "junit":
            _write(render_junit(result.summaries), output_file)
        else:
            _print_text_report(result.report)

        if html:
            written = service.generate_report(
                target_id=target, profile=profile, formats=["html"]
            )
            typer.secho(f"\nHTML report: {written['written']['html']}", fg=typer.colors.CYAN)

        raise typer.Exit(result.exit_code)
    except AgentSecError as exc:
        _fail(exc)


def _write(payload: str, path: Path | None) -> None:
    if path is None:
        typer.echo(payload)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    typer.secho(f"wrote {path}", fg=typer.colors.CYAN, err=True)


_VERDICT_COLOUR = {
    "secure": typer.colors.GREEN,
    "detection_gap": typer.colors.RED,
    "prevention_gap": typer.colors.RED,
    "evidence_gap": typer.colors.YELLOW,
    "response_gap": typer.colors.YELLOW,
    "error": typer.colors.MAGENTA,
}


def _print_text_report(report: dict) -> None:
    typer.echo(
        f"\ntarget {report['target_id']}  profile {report['profile']}  "
        f"runs {report['total_runs']}\n"
    )
    for r in report["runs"]:
        colour = _VERDICT_COLOUR.get(r["purple_verdict"], typer.colors.WHITE)
        flag = " [BLOCKING]" if r["blocking"] else ""
        typer.secho(f"  {r['purple_verdict']:<15}{flag} {r['scenario_id']}  "
                    f"{r['scenario_title']}", fg=colour)
        typer.echo(
            f"      prevention={r['prevention']} detection={r['detection']} "
            f"evidence={r['evidence']} response={r['response']}"
        )
        if r["rationale"]:
            typer.echo(f"      {r['rationale']}")
        for c in r["failed_checks"][:4]:
            typer.echo(f"        - [{c['axis']}] {c['assertion']}")
            typer.echo(f"          observed: {c['observed']}")

    typer.echo("")
    if report["blocking_count"]:
        typer.secho(
            f"{report['blocking_count']} blocking finding(s): "
            f"{', '.join(report['blocking_scenarios'])}",
            fg=typer.colors.RED, bold=True,
        )
    else:
        typer.secho("no blocking findings", fg=typer.colors.GREEN, bold=True)


# --------------------------------------------------------------------------
# results
# --------------------------------------------------------------------------


@app.command("get-run")
def get_run(run_id: str, workspace: WorkspaceOpt = None) -> None:
    """Print one run as JSON."""
    try:
        _echo_json(_service(workspace).get_run(run_id).model_dump(mode="json"))
    except AgentSecError as exc:
        _fail(exc)


@app.command()
def compare(run_a: str, run_b: str, workspace: WorkspaceOpt = None) -> None:
    """Diff two runs check-by-check."""
    try:
        _echo_json(_service(workspace).compare_runs(run_a=run_a, run_b=run_b))
    except AgentSecError as exc:
        _fail(exc)


@app.command()
def report(
    target: Annotated[str | None, typer.Option("--target", "-t")] = None,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Restrict to one profile; omit for all."),
    ] = None,
    limit: Annotated[int, typer.Option("--limit")] = 50,
    formats: Annotated[
        list[str] | None, typer.Option("--format", "-f", help="html | json | junit")
    ] = None,
    workspace: WorkspaceOpt = None,
) -> None:
    """Render recent runs as HTML/JSON/JUnit."""
    try:
        _echo_json(
            _service(workspace).generate_report(
                target_id=target, profile=profile, limit=limit,
                formats=formats or ["html", "json"],
            )
        )
    except AgentSecError as exc:
        _fail(exc)


@app.command()
def audit(
    limit: Annotated[int, typer.Option("--limit")] = 50, workspace: WorkspaceOpt = None
) -> None:
    """Show the tail of the audit log, including refused requests."""
    try:
        _echo_json(_service(workspace).store.audit_tail(limit))
    except AgentSecError as exc:
        _fail(exc)


# --------------------------------------------------------------------------
# findings and approvals
# --------------------------------------------------------------------------


@finding_app.command("list")
def finding_list(
    status: Annotated[str | None, typer.Option("--status")] = None,
    workspace: WorkspaceOpt = None,
) -> None:
    """List findings."""
    try:
        _echo_json(_service(workspace).list_findings(status=status))
    except AgentSecError as exc:
        _fail(exc)


@finding_app.command("promote")
def finding_promote(
    finding_id: str,
    status: Annotated[str, typer.Option("--status")],
    regression: Annotated[str | None, typer.Option("--regression")] = None,
    detection: Annotated[str | None, typer.Option("--detection")] = None,
    note: Annotated[str | None, typer.Option("--note")] = None,
    workspace: WorkspaceOpt = None,
) -> None:
    """Advance a finding through its workflow."""
    try:
        _echo_json(
            _service(workspace).promote_finding(
                finding_id=finding_id, status=status,
                regression_test_ref=regression, detection_rule_ref=detection, note=note,
            )
        )
    except AgentSecError as exc:
        _fail(exc)


@finding_app.command("draft-regression")
def finding_draft(finding_id: str, workspace: WorkspaceOpt = None) -> None:
    """Print a regression scenario draft for a finding."""
    try:
        draft = _service(workspace).create_regression_draft(finding_id=finding_id)
        typer.secho(f"# suggested path: {draft['suggested_path']}", fg=typer.colors.CYAN)
        typer.echo(draft["yaml"])
    except AgentSecError as exc:
        _fail(exc)


@app.command()
def approve(
    scenario: Annotated[str, typer.Option("--scenario", "-s")],
    target: Annotated[str, typer.Option("--target", "-t")],
    ttl: Annotated[int, typer.Option("--ttl", help="Minutes until the token expires.")] = 60,
    reason: Annotated[str, typer.Option("--reason")] = "",
    by: Annotated[str | None, typer.Option("--by")] = None,
    workspace: WorkspaceOpt = None,
) -> None:
    """Grant a single-use approval token for a high-risk scenario.

    Deliberately CLI-only: no MCP tool mints approvals, so a model cannot approve
    its own request.
    """
    try:
        service = _service(workspace)
        approval = service.approvals.grant(
            scenario_id=scenario, target_id=target,
            approved_by=by or service.actor, ttl_minutes=ttl, reason=reason,
        )
        service.store.audit(
            actor=service.actor, action="approve", subject=scenario,
            outcome="granted", detail={"target_id": target, "ttl_minutes": ttl},
        )
        _echo_json(approval.model_dump(mode="json"))
    except AgentSecError as exc:
        _fail(exc)


@app.command("validate-detection")
def validate_detection(
    scenario: Annotated[str, typer.Option("--scenario", "-s")],
    target: Annotated[str, typer.Option("--target", "-t")],
    workspace: WorkspaceOpt = None,
) -> None:
    """Check a scenario's detection expectations are checkable against a target."""
    try:
        _echo_json(
            _service(workspace).validate_detection(scenario_id=scenario, target_id=target)
        )
    except AgentSecError as exc:
        _fail(exc)


@app.command("mcp-contract")
def mcp_contract() -> None:
    """Print the MCP tool/resource surface as JSON (used to generate docs)."""
    from agentsec.mcp.contract import contract_summary

    _echo_json(contract_summary())


def main() -> None:
    try:
        app()
    except AgentSecError as exc:  # pragma: no cover - safety net
        typer.secho(f"error [{exc.code}]: {exc.message}", fg=typer.colors.RED, err=True)
        sys.exit(EXIT_ERROR)


if __name__ == "__main__":  # pragma: no cover
    main()
