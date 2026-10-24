"""Static HTML report.

Deliberately a single self-contained file with no external assets: it has to be
attachable to a ticket, openable from a CI artifact zip, and readable on a
machine with no network. That constraint is also what makes it a drop-in source
for a Live Artifact later.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATE_DIR = Path(__file__).parent / "templates"

_STATUS_CLASS = {
    "pass": "pass",
    "fail": "fail",
    "error": "warn",
    "not_tested": "skip",
}

_VERDICT_CLASS = {
    "secure": "pass",
    "detection_gap": "fail",
    "prevention_gap": "fail",
    "evidence_gap": "warn",
    "response_gap": "warn",
    "error": "warn",
}

_UNSAFE_FRAGMENT = re.compile(r"[^A-Za-z0-9_-]+")


def _fragment_id(prefix: str, value: object) -> str:
    """Return a stable local-link target without trusting a DTO value as markup."""
    cleaned = _UNSAFE_FRAGMENT.sub("-", str(value)).strip("-") or "unknown"
    return f"{prefix}-{cleaned}"


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals["status_class"] = lambda s: _STATUS_CLASS.get(s, "skip")
    env.globals["verdict_class"] = lambda v: _VERDICT_CLASS.get(v, "skip")
    env.globals["scenario_anchor"] = lambda value: _fragment_id("scenario", value)
    env.globals["run_anchor"] = lambda value: _fragment_id("run", value)
    return env


def render_html_report(batch: dict[str, Any], coverage: dict[str, Any] | None = None) -> str:
    template = _environment().get_template("report.html.j2")
    return template.render(batch=batch, coverage=coverage)


def render_dashboard(
    document: dict[str, Any], findings: list[dict[str, Any]] | None = None
) -> str:
    """The Live Artifact page, rendered from the published dashboard document.

    Takes the *published* document — the one `publish("dashboard", …)` returned —
    rather than the service's internal dict, so the page can only render fields
    that survived projection. Nothing here reaches back into the store, which is
    what makes "this page cannot leak an evidence bundle" a property of the
    plumbing rather than of the template's good manners.

    The same file is the renderer for a Claude Code Live Artifact and for a page
    written to disk: the intended Live Artifact consumer can re-read the gateway
    resource on refresh, while the local file is a snapshot of the moment it was
    written. Both render from this template, so a reader comparing them is
    comparing data rather than two renderers.
    """
    template = _environment().get_template("dashboard.html.j2")
    runs = document.get("purple", {}).get("runs", [])
    runs_by_scenario: dict[str, list[dict[str, Any]]] = {}
    for run in runs:
        if isinstance(run, dict) and isinstance(run.get("scenario_id"), str):
            runs_by_scenario.setdefault(run["scenario_id"], []).append(run)
    return template.render(
        d=document,
        findings=findings or [],
        runs_by_scenario=runs_by_scenario,
    )


def write_dashboard(
    path: Path, document: dict[str, Any], findings: list[dict[str, Any]] | None = None
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_dashboard(document, findings), encoding="utf-8")
    return path


def write_html_report(
    path: Path, batch: dict[str, Any], coverage: dict[str, Any] | None = None
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_report(batch, coverage), encoding="utf-8")
    return path
