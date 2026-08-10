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
project_app = typer.Typer(help="Inspect the selected project.", no_args_is_help=True)
app.add_typer(targets_app, name="targets")
app.add_typer(scenarios_app, name="scenarios")
app.add_typer(finding_app, name="finding")
app.add_typer(project_app, name="project")

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


# --------------------------------------------------------------------------
# project
# --------------------------------------------------------------------------


@app.command()
def init(
    project_id: Annotated[
        str | None,
        typer.Option("--project-id", help="Stable id for this repository. Defaults to its name."),
    ] = None,
    name: Annotated[str | None, typer.Option("--name")] = None,
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing manifest.")] = False,
    workspace: WorkspaceOpt = None,
) -> None:
    """Write `.agentsec/project.yaml` for the selected repository.

    The file is a starting point, not an installation: commit it after reading
    it. It is reviewed like the target allowlist, because it decides what the
    harness will read.
    """
    from agentsec.project import (
        MANIFEST_PATH,
        default_manifest_text,
        manifest_path,
        resolve_root,
        suggest_project_id,
    )

    try:
        root = resolve_root(workspace)
    except AgentSecError as exc:
        _fail(exc)
        return

    path = manifest_path(root)
    if path.exists() and not force:
        typer.secho(
            f"{MANIFEST_PATH} already exists. Edit it, or pass --force to replace it.",
            fg=typer.colors.YELLOW, err=True,
        )
        raise typer.Exit(EXIT_ERROR)

    text = default_manifest_text(
        project_id=project_id or suggest_project_id(root),
        name=name or root.name,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    typer.secho(f"wrote {MANIFEST_PATH}", fg=typer.colors.GREEN)
    typer.echo("Review it, then commit it. Run `agentsec project show` to see what it discovers.")


_SEVERITY_COLOUR = {
    "critical": typer.colors.RED,
    "high": typer.colors.RED,
    "medium": typer.colors.YELLOW,
    "low": typer.colors.CYAN,
    "info": typer.colors.WHITE,
}
_VERIFICATION_LABEL = {
    "verified": "verified by a run",
    "verifiable": "runnable now",
    "not_verifiable": "no scenario covers this",
}
#: What each classification means to someone who did not read the schema. Every
#: line says what was found; none of them says the repository is safe, because
#: this classifier has executed nothing.
_PRESENCE_LABEL = {
    "confirmed": ("confirmed", typer.colors.CYAN),
    "likely": ("likely", typer.colors.CYAN),
    "configuration_only": ("configuration only", typer.colors.WHITE),
    "not_detected": ("not detected", typer.colors.WHITE),
    "unsupported": ("could not classify", typer.colors.YELLOW),
}
_PRESENCE_DETAIL = {
    "confirmed": "runtime agent code in this repository",
    "likely": "agent dependencies or tool calling, but no runtime entrypoint",
    "configuration_only": "coding-agent configuration only — no runtime agent code",
    "not_detected": "no agent framework, tool calling or agent configuration found",
    "unsupported": "something was found here that these rules cannot classify",
}


@app.command()
def scan(
    verify: Annotated[
        bool,
        typer.Option(
            "--verify",
            help="Hand the verifiable high/critical risks to the harness for a verdict.",
        ),
    ] = False,
    target: Annotated[
        str | None,
        typer.Option("--target", "-t", help="Target to verify against. Required with --verify."),
    ] = None,
    profile: Annotated[str, typer.Option("--profile", "-p")] = "pr",
    output: Annotated[str, typer.Option("--output", "-o", help="text | json")] = "text",
    workspace: WorkspaceOpt = None,
) -> None:
    """Inspect the selected repository for agent attack surface, and rank what it finds.

    The engineer's entry point. Answers two questions in order: whether this
    repository implements an AI agent — and in what framework — then what in its
    skills, agents, hooks, tool grants, MCP servers and memory stores is worth
    testing, with whether anything here can turn each risk into a deterministic
    conclusion.

    The first answer never asserts the second. A repository holding only a
    `CLAUDE.md` and a `.mcp.json` reports `configuration only`: a coding agent
    works *on* this checkout, which is not the same as this checkout *being* an
    agent. `not detected` is likewise an absence of evidence, not a pass.

    Static only, by design. A risk is a reason to run a scenario, never the
    result of having run one — so `--verify` is the second half: it selects the
    scenarios that cover the high and critical risks and runs them, and the
    verdict comes from the Purple Harness exactly as it does for `agentsec run`.

    Exit codes match the rest of the CLI: `1` when a run started and found a
    blocking finding, `2` when the repository could not be inspected at all.
    Notably *not* `1` for a static risk on its own — a rule match is not proof,
    and a gate that blocks on one teaches its team to bypass the gate.
    """
    try:
        service = _service(workspace)
        document = service.inspect_repository()
        plane = document["repo_risk"]

        if output == "json":
            _echo_json(document)
        else:
            _print_scan(document)

        if not verify:
            raise typer.Exit(EXIT_OK)

        queue = plane.get("verify_queue") or []
        if not queue:
            typer.secho(
                "\nnothing to verify: no high or critical risk has a scenario that covers it",
                fg=typer.colors.YELLOW,
            )
            raise typer.Exit(EXIT_OK)
        if not target:
            typer.secho(
                "--verify needs --target: a verdict is always against a specific target.",
                fg=typer.colors.RED, err=True,
            )
            raise typer.Exit(EXIT_ERROR)

        typer.secho(
            f"\nverifying {len(queue)} scenario(s) against {target}: {', '.join(queue)}",
            fg=typer.colors.CYAN, bold=True,
        )
        result = service.start_run(
            target_id=target, scenario_ids=list(queue), profile=profile
        )
        _print_text_report(result.report)
        raise typer.Exit(result.exit_code)
    except AgentSecError as exc:
        _fail(exc)


def _print_agent(project: dict) -> None:
    """What this repository *is*, before what is wrong with it.

    First, because it is the question an engineer opening an unfamiliar
    repository actually has, and because every risk below it means something
    different depending on the answer. Printed even when the risk plane could
    not run: whether there is an agent here does not depend on whether anyone
    has run `agentsec init`.
    """
    fingerprint = project.get("fingerprint") or {}
    presence = fingerprint.get("agent_presence", "unsupported")
    label, colour = _PRESENCE_LABEL.get(presence, (presence, typer.colors.YELLOW))

    typer.secho(f"\n  AI agent      {label}", fg=colour, bold=True)
    typer.echo(f"                {_PRESENCE_DETAIL.get(presence, '')}")

    for agent in fingerprint.get("runtime_agents") or []:
        where = ", ".join(agent.get("entrypoints") or []) or "no entrypoint found"
        typer.echo(f"                {agent['framework']} ({agent['language']})  {where}")
    platforms = ", ".join(
        config["platform"] for config in fingerprint.get("development_agent_config") or []
    )
    if platforms:
        typer.echo(f"                coding-agent config: {platforms}")
    if fingerprint.get("problems"):
        typer.secho(
            f"                {len(fingerprint['problems'])} file(s) could not be parsed; "
            "absence of a framework here is not proof there is none",
            fg=typer.colors.YELLOW,
        )


def _print_scan(document: dict) -> None:
    project, plane = document["project"], document["repo_risk"]
    _print_agent(project)

    if plane.get("status") != "inspected":
        typer.secho(
            f"\nnot inspected [{plane.get('reason', 'unknown')}]: {plane.get('detail', '')}",
            fg=typer.colors.YELLOW,
        )
        return

    typer.echo(
        f"\n  project       {project.get('project_id', '?')}  "
        f"surfaces {sum((project.get('surfaces') or {}).values())}  "
        f"risks {plane['counts']['total']}\n"
    )

    for risk in plane["risks"]:
        colour = _SEVERITY_COLOUR.get(risk["severity"], typer.colors.WHITE)
        state = risk["verification"]["state"]
        typer.secho(f"  {risk['severity']:<9}{risk['rule_id']}  {risk['file']}", fg=colour)
        typer.echo(f"      {risk['title']}")
        label = _VERIFICATION_LABEL.get(state, state)
        scenarios = ", ".join(risk["verification"].get("scenario_ids") or [])
        typer.echo(f"      verification: {label}{f' ({scenarios})' if scenarios else ''}")

    if plane.get("problems"):
        typer.secho(
            f"\n{len(plane['problems'])} surface(s) could not be read:", fg=typer.colors.YELLOW
        )
        for problem in plane["problems"][:10]:
            typer.echo(f"    [{problem['kind']}] {problem['path']}: {problem['detail']}")

    by_verification = plane["counts"]["by_verification"]
    typer.echo("")
    if not plane["risks"]:
        typer.secho(
            "no risks matched. That is not a clean bill of health: these are static "
            "rules over configuration, and nothing has been executed.",
            fg=typer.colors.GREEN,
        )
        return
    typer.secho(
        f"{by_verification['verified']} verified  "
        f"{by_verification['verifiable']} runnable  "
        f"{by_verification['not_verifiable']} unprovable here",
        bold=True,
    )
    if by_verification["verifiable"]:
        typer.secho(
            "run `agentsec scan --verify --target <id>` to turn the runnable ones "
            "into verdicts.",
            fg=typer.colors.CYAN,
        )
    if by_verification["not_verifiable"]:
        typer.secho(
            "the unprovable ones have no scenario covering their surface. They are "
            "neither passing nor failing — nothing here can settle them.",
            fg=typer.colors.YELLOW,
        )


@app.command()
def dashboard(
    target: Annotated[str | None, typer.Option("--target", "-t")] = None,
    profile: Annotated[str | None, typer.Option("--profile", "-p")] = None,
    html: Annotated[
        Path | None,
        typer.Option("--html", help="Also write the dashboard page to this path."),
    ] = None,
    workspace: WorkspaceOpt = None,
) -> None:
    """Print the composed project dashboard — the same document the MCP resource serves.

    Reads only. Unlike `agentsec report`, this writes nothing unless `--html`
    names a file: it is the shape a dashboard polls, and a poll that leaves
    files behind is one nobody can automate. `--html` renders the same page a
    hosted Live Artifact shows, as a snapshot for a ticket or a CI artifact.
    """
    from agentsec.reporting.html import write_dashboard
    from agentsec.reporting.publish import publish

    try:
        service = _service(workspace)
        document = publish("dashboard", service.dashboard(target_id=target, profile=profile))
        if html is not None:
            findings = [f for f in service.list_findings() if f["status"] != "closed"]
            write_dashboard(html, document, publish("findings", findings)["findings"])
            typer.secho(f"wrote {html}", fg=typer.colors.GREEN, err=True)
        _echo_json(document)
    except AgentSecError as exc:
        _fail(exc)


@project_app.command("show")
def project_show(workspace: WorkspaceOpt = None) -> None:
    """Inventory the selected project: skills, agents, hooks, settings, MCP config.

    An inventory, never a verdict. `skill_assurance` reports `not_tested` in
    every case today, with a reason distinguishing "nothing to test" from
    "nothing to test with".
    """
    from agentsec.project import discover

    try:
        _echo_json(discover(workspace).to_dict())
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
