"""Static HTML report.

Deliberately a single self-contained file with no external assets: it has to be
attachable to a ticket, openable from a CI artifact zip, and readable on a
machine with no network. That constraint is also what makes it a drop-in source
for a Live Artifact later.
"""

from __future__ import annotations

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


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals["status_class"] = lambda s: _STATUS_CLASS.get(s, "skip")
    env.globals["verdict_class"] = lambda v: _VERDICT_CLASS.get(v, "skip")
    return env


def render_html_report(batch: dict[str, Any], coverage: dict[str, Any] | None = None) -> str:
    template = _environment().get_template("report.html.j2")
    return template.render(batch=batch, coverage=coverage)


def write_html_report(
    path: Path, batch: dict[str, Any], coverage: dict[str, Any] | None = None
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_report(batch, coverage), encoding="utf-8")
    return path
