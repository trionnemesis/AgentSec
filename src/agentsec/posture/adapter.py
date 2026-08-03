"""Ingest a static scanner's report — AgentShield's native JSON, or SARIF.

Nothing here runs a scanner, vendors one, or shells out to `npx`. It reads a
report file someone else's tool already produced, at a location the project
manifest declared (`.agentsec/project.yaml: static_posture_report`), and
refuses anything it does not recognise rather than reporting an empty pass.
SARIF is accepted alongside AgentShield's own format because it is what makes
this ingestion portable to any other scanner that emits it — see issue #25.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentsec.errors import PostureIngestionError
from agentsec.models.posture import PostureReport, Severity, StaticPostureFinding
from agentsec.project.resolver import safe_child

#: SARIF's four severity levels, mapped onto ours. SARIF has no `critical`; a
#: driver wanting one expresses it via `properties.security-severity`, which
#: this adapter does not attempt to parse — an approximate, documented mapping
#: beats a silent drop.
_SARIF_LEVEL: dict[str, Severity] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}

_KNOWN_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


def resolve_report_path(root: Path, location: str) -> Path:
    """Resolve the manifest-declared report location, refusing anything outside
    the project root — the same rule every other declared location follows."""
    return safe_child(root, location, field="static_posture_report")


def load_posture_report(path: Path) -> PostureReport:
    """Parse the report at ``path`` into the normalised shape.

    Raises :class:`PostureIngestionError` on anything this version does not
    recognise. A caller with no report configured never calls this — "no
    report" is a ``not_tested`` state the caller produces itself, not an empty
    :class:`PostureReport` returned from here.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PostureIngestionError(f"cannot read static posture report: {exc}") from exc
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PostureIngestionError(f"static posture report is not valid JSON: {exc}") from exc

    if not isinstance(raw, dict):
        raise PostureIngestionError("static posture report is not a JSON object")

    if _looks_like_sarif(raw):
        return _from_sarif(raw)
    if _looks_like_agentshield(raw):
        return _from_agentshield(raw)

    version_hint = raw.get("version") or raw.get("$schema") or raw.get("schemaVersion")
    raise PostureIngestionError(
        "unrecognised static posture report shape: expected AgentShield JSON "
        "(top-level 'findings' and 'score') or SARIF ('version' and 'runs')",
        details={
            "top_level_keys": sorted(raw),
            "version": version_hint,
        },
    )


def _looks_like_sarif(raw: dict[str, Any]) -> bool:
    return isinstance(raw.get("runs"), list) and (
        "version" in raw or str(raw.get("$schema", "")).lower().find("sarif") != -1
    )


def _looks_like_agentshield(raw: dict[str, Any]) -> bool:
    return isinstance(raw.get("findings"), list) and isinstance(raw.get("score"), dict)


# -- AgentShield native JSON --------------------------------------------------


def _from_agentshield(raw: dict[str, Any]) -> PostureReport:
    version = raw.get("version") or raw.get("toolVersion")
    version = str(version) if version is not None else None
    findings = [
        _agentshield_finding(row, version)
        for row in raw["findings"]
        if isinstance(row, dict)
    ]
    return PostureReport(source_tool="agentshield", source_version=version, findings=findings)


def _agentshield_finding(row: dict[str, Any], version: str | None) -> StaticPostureFinding:
    severity = str(row.get("severity", "")).lower()
    if severity not in _KNOWN_SEVERITIES:
        raise PostureIngestionError(
            f"AgentShield finding {row.get('id')!r} has an unrecognised severity: "
            f"{row.get('severity')!r}"
        )
    rule_id = str(row.get("id") or "")
    if not rule_id:
        raise PostureIngestionError("AgentShield finding has no 'id'")
    file_path = str(row.get("file") or "")
    if not file_path:
        raise PostureIngestionError(f"AgentShield finding {rule_id!r} has no 'file'")
    return StaticPostureFinding(
        rule_id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        category=str(row.get("category") or "uncategorised"),
        file=file_path,
        title=str(row.get("title") or rule_id)[:300],
        source_tool="agentshield",
        source_version=version,
    )


# -- SARIF 2.1.0 ---------------------------------------------------------------


def _from_sarif(raw: dict[str, Any]) -> PostureReport:
    runs = raw.get("runs")
    if not isinstance(runs, list) or not runs:
        raise PostureIngestionError("SARIF report has no 'runs'")

    tool_name = "sarif"
    tool_version: str | None = None
    findings: list[StaticPostureFinding] = []

    for run in runs:
        if not isinstance(run, dict):
            continue
        driver = ((run.get("tool") or {}).get("driver")) or {}
        if isinstance(driver.get("name"), str) and driver["name"]:
            tool_name = driver["name"].lower()
        if isinstance(driver.get("version"), str):
            tool_version = driver["version"]
        rule_meta = {
            r["id"]: r
            for r in (driver.get("rules") or [])
            if isinstance(r, dict) and isinstance(r.get("id"), str)
        }
        for result in run.get("results") or []:
            if isinstance(result, dict):
                findings.append(_sarif_finding(result, rule_meta, tool_name, tool_version))

    return PostureReport(source_tool=tool_name, source_version=tool_version, findings=findings)


def _sarif_finding(
    result: dict[str, Any],
    rule_meta: dict[str, dict[str, Any]],
    tool_name: str,
    tool_version: str | None,
) -> StaticPostureFinding:
    rule_id = str(result.get("ruleId") or "")
    if not rule_id:
        raise PostureIngestionError("SARIF result has no 'ruleId'")
    rule = rule_meta.get(rule_id, {})

    level = str(
        result.get("level")
        or (rule.get("defaultConfiguration") or {}).get("level")
        or "warning"
    ).lower()
    severity = _SARIF_LEVEL.get(level, "medium")

    locations = result.get("locations")
    file_path = ""
    if isinstance(locations, list) and locations and isinstance(locations[0], dict):
        physical = locations[0].get("physicalLocation") or {}
        file_path = (physical.get("artifactLocation") or {}).get("uri", "")
    if not file_path:
        raise PostureIngestionError(f"SARIF result for rule {rule_id!r} has no file location")

    message = (result.get("message") or {}).get("text") or (
        (rule.get("shortDescription") or {}).get("text")
    ) or rule_id
    category = (
        (rule.get("properties") or {}).get("category")
        or (result.get("properties") or {}).get("category")
        or "uncategorised"
    )

    return StaticPostureFinding(
        rule_id=rule_id,
        severity=severity,
        category=str(category),
        file=str(file_path),
        title=str(message)[:300],
        source_tool=tool_name,
        source_version=tool_version,
    )
