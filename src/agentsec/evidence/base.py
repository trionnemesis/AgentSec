"""Shared plumbing for evidence collectors."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentsec.errors import EvidenceUnavailable
from agentsec.models.target import Target


@dataclass(frozen=True)
class CollectContext:
    run_id: str
    scenario_id: str
    target: Target
    workspace: Path
    window_start: datetime
    window_end: datetime
    # Marks the bundled fixture execution workflow. Collectors may use the
    # recorded-corpus placeholder only for their file backend; live HTTP and
    # OpenSearch sources must never inherit this exemption.
    trusted_fixture: bool = False


def resolve_path(raw: str | None, ctx: CollectContext) -> Path:
    """Resolve a backend path, expanding ``{run_id}`` and ``{scenario_id}``.

    Templating lets one target definition serve a whole fixture corpus, which is
    what keeps the offline demo from needing a target per scenario.
    """
    if not raw:
        raise EvidenceUnavailable("backend is missing a 'path'")
    expanded = raw.format(run_id=ctx.run_id, scenario_id=ctx.scenario_id)
    path = Path(expanded)
    return path if path.is_absolute() else ctx.workspace / path


def read_json(path: Path) -> Any:
    if not path.is_file():
        raise EvidenceUnavailable(f"evidence file not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EvidenceUnavailable(f"malformed evidence file {path.name}: {exc}") from exc


def read_jsonl(path: Path) -> list[Any]:
    if not path.is_file():
        raise EvidenceUnavailable(f"evidence file not found: {path}")
    rows: list[Any] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise EvidenceUnavailable(
                f"malformed JSONL at {path.name}:{lineno}: {exc}"
            ) from exc
    return rows


def rebase_to_window(timestamps: list[datetime], window_start: datetime) -> list[datetime]:
    """Shift a fixture's timeline so its first record lands on ``window_start``.

    Recorded evidence carries the wall-clock time of the day it was captured.
    Latency assertions (``within_seconds``) compare against the *current* run's
    window, so an unshifted fixture either rots the moment the clock passes its
    timestamps or fails whenever the deadline is tighter than the gap between
    then and now — in both cases reporting a detection gap that is really a
    calendar artefact.

    Relative offsets are preserved, so an alert recorded three seconds after the
    first event still tests ``within_seconds: 3`` honestly. Only file-backed
    (fixture) collection rebases; live backends already query the real window.
    """
    if not timestamps:
        return []
    aware = [t if t.tzinfo else t.replace(tzinfo=UTC) for t in timestamps]
    earliest = min(aware)
    delta = window_start - earliest
    return [t + delta for t in aware]


def flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten a nested document to dot-notation keys.

    Assertions are written as ``data.tenant_id: tenant-b``, so both Wazuh
    documents and OTel attribute bags get flattened into the same shape before
    matching.
    """
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict | list):
                out.update(flatten(value, child))
            else:
                out[child] = value
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            child = f"{prefix}.{i}" if prefix else str(i)
            if isinstance(value, dict | list):
                out.update(flatten(value, child))
            else:
                out[child] = value
        if prefix:
            # Also expose the joined scalar list, so `rule.groups: authentication`
            # matches without the author having to guess an index.
            scalars = [v for v in obj if not isinstance(v, dict | list)]
            if scalars:
                out.setdefault(prefix, ",".join(str(s) for s in scalars))
    else:
        out[prefix or "value"] = obj
    return out


def canonical_run_id(raw: Any) -> str | None:
    """Read the canonical ``agentsec.run_id`` from this object only.

    Backends encode the field either as a direct dotted key or as a direct
    ``agentsec`` object.  Deliberately do not recurse or accept a generic
    ``run_id``: attacker-controlled arguments and unrelated backend fields are
    not correlation proof.  If both supported encodings are present, they must
    agree.
    """
    if not isinstance(raw, dict):
        return None
    observed: list[str] = []
    value = raw.get("agentsec.run_id")
    if value not in (None, ""):
        observed.append(str(value))
    agentsec = raw.get("agentsec")
    if isinstance(agentsec, dict):
        value = agentsec.get("run_id")
        if value not in (None, ""):
            observed.append(str(value))
    if not observed:
        return None
    if any(value != observed[0] for value in observed[1:]):
        raise EvidenceUnavailable("conflicting canonical agentsec.run_id values")
    return observed[0]


def require_run_id(
    observed: str | None,
    ctx: CollectContext,
    *,
    what: str,
) -> str:
    """Enforce current-run correlation, with the explicit fixture boundary."""
    return require_run_id_value(
        observed, ctx.run_id, trusted_fixture=ctx.trusted_fixture, what=what
    )


def require_run_id_value(
    observed: str | None,
    expected: str,
    *,
    trusted_fixture: bool,
    what: str,
) -> str:
    """Value-only variant used by backend parsers before a full context exists."""
    if observed == expected:
        return expected
    if observed is None and trusted_fixture:
        return expected
    if observed is None:
        raise EvidenceUnavailable(f"{what} is missing canonical agentsec.run_id")
    raise EvidenceUnavailable(f"{what} is correlated to another run")


def rebase_timestamp(
    timestamp: datetime | None,
    window_start: datetime,
    *,
    earliest: datetime | None = None,
) -> datetime | None:
    """Rebase one recorded fixture timestamp while retaining its relative time."""
    if timestamp is None:
        return None
    aware = timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=UTC)
    origin = earliest or aware
    if origin.tzinfo is None:
        origin = origin.replace(tzinfo=UTC)
    return aware + (window_start - origin)
