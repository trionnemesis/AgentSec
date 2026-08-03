"""Publishable projections of everything a run observes.

``Target.redacted()`` decides what target *configuration* may leave the process.
This is the equivalent for what a run *sees*, and the line between the two is the
whole policy:

* **Declared configuration** — what an operator wrote in ``policy/targets.yaml``,
  what a scenario author committed and a reviewer merged — has already been
  reviewed and already has its credentials held back. It passes through.
* **Observed data** — transcript turns, span attributes, alert fields, tenant
  ids, audit detail — is whatever the system under test happened to emit. In a
  cross-tenant scenario that is, by construction, the record that leaked.

Observed data is therefore projected rather than filtered: each publisher names
the fields it keeps, so a field added to an evidence model tomorrow is absent
from published output until someone decides it belongs there. A filter would
have shipped it.

Two properties this module is built to hold:

**Fail closed.** :func:`publish` dispatches through a registry keyed by output
kind and raises when a kind has no policy. A new MCP resource whose output has
no publisher stops the gateway from starting rather than serving raw models.

**Redaction is visible.** Every projection carries a ``redaction`` block naming
what was dropped. A reader who sees no transcript should be able to tell that
one existed and was withheld, rather than concluding the run had none — the same
reason an untested axis reports ``not_tested`` instead of rounding up to a pass.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable
from functools import lru_cache
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from agentsec.errors import AgentSecError
from agentsec.models.evidence import Evidence
from agentsec.models.run import Run

#: Bumped when a published shape changes in a way a consumer would notice.
#: A Live Artifact or MCP App can pin against it; see ``schemas/dashboard.schema.json``.
#: 1.1.0 added `provenance` per run and `provenance_counts`/`fixture_derived` on
#: the rollup (#27) — additive only, so a consumer pinned to 1.x still validates.
#: 1.2.0 added the `static_posture` plane to the composed dashboard (#25) — a
#: new *required* key on the `dashboard` kind, so a consumer pinned there does
#: notice; `report`/`purple` on their own are unaffected.
PUBLISH_SCHEMA_VERSION = "1.2.0"

#: Names the ruleset, so a stored export says which policy produced it.
PUBLISH_POLICY = "observed-data-v1"

#: Free text is capped before publication. Every string that reaches a published
#: field today is evaluator-authored and quotes only values declared in the
#: scenario, so this changes nothing now; it is here so that an evaluator change
#: which starts echoing target output cannot turn a report into an exfiltration
#: channel without someone noticing the truncation.
MAX_TEXT = 500

ENV_SALT = "AGENTSEC_PSEUDONYM_SALT"

#: Pseudonyms preserve *correlation* without printing the identifier: two turns
#: by the same principal share a label, so a reader can still see the pivot that
#: made the scenario interesting. They are not anonymisation. The identifier
#: space is small and this default salt ships in the source, so anyone holding
#: both can invert them by enumeration. Set ``AGENTSEC_PSEUDONYM_SALT`` per
#: deployment whenever the reader is less trusted than whoever can read this file.
_DEFAULT_SALT = b"agentsec-publish-v1"

#: Span and alert values are dropped by default and kept only for these keys.
#: Every entry is a value the emitting convention defines, not one the agent
#: chooses: a status code cannot carry an order record, ``gen_ai.tool.name`` is
#: drawn from the target's own tool list. Anything the agent authors — arguments,
#: prompts, retrieved documents — is absent from this list on purpose.
SAFE_ATTRIBUTE_KEYS: frozenset[str] = frozenset(
    {
        "http.status_code",
        "gen_ai.operation.name",
        "gen_ai.system",
        "gen_ai.tool.name",
        "rpc.method",
        "agentsec.decision",
        "agentsec.policy",
    }
)

_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://\S+", re.I)
_APPROVAL = re.compile(r"\bapr_[0-9a-f]{16}\b")
#: ``bearer`` takes a bare value; the rest need an explicit ``:`` or ``=``. A
#: sentence like "no secret found" is prose about a credential, not one, and
#: mangling it costs a reader the message without protecting anything.
_BEARER = re.compile(
    r"\bbearer\s+\S+"
    # `Authorization: Bearer abc` is one credential, not a labelled scheme
    # followed by a loose word, so the value swallows the scheme too.
    r"|\b(?:token|api[_-]?key|password|secret|authorization)\b\s*[:=]\s*(?:bearer\s+)?\S+",
    re.I,
)
#: 24+ unbroken characters mixing at least three letters and three digits: long
#: and mixed enough to be a key, while ``agentsec_create_regression_draft`` and a
#: run of repeated characters are neither. An identifier that happens to look
#: like a token is a false positive worth having; a key that reaches a dashboard
#: is not.
_HIGH_ENTROPY = re.compile(
    r"\b(?=(?:[^0-9\s]*[0-9]){3})(?=(?:[^A-Za-z\s]*[A-Za-z]){3})"
    r"[A-Za-z0-9+/_-]{24,}={0,2}\b"
)


class RedactionError(AgentSecError):
    """No publication policy exists for this output type."""

    code = "redaction_policy_missing"


class PublicationInvalid(AgentSecError):
    """A projected document does not match the schema consumers pin to.

    Refusing to serve is the fail-closed answer: a consumer that pinned to the
    published schema cannot see a silently-changed shape, but it can see an
    error.
    """

    code = "publication_schema_invalid"


def _salt() -> bytes:
    configured = os.environ.get(ENV_SALT, "").strip()
    return configured.encode("utf-8") if configured else _DEFAULT_SALT


def pseudonym(prefix: str, value: str | None) -> str | None:
    """Stable label for an identifier that must not be printed.

    Deterministic for a given salt, so the same principal reads the same across
    runs and a reader can follow it between turns.
    """
    if value is None:
        return None
    digest = hashlib.blake2s(value.encode("utf-8"), digest_size=4, key=_salt()).hexdigest()
    return f"{prefix}_{digest}"


def digest(value: str | None) -> str | None:
    """Content fingerprint, for comparing two turns without reading either."""
    if value is None:
        return None
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def scrub(text: str | None) -> str | None:
    """Strip locators and credential-shaped runs out of free text, then cap it.

    Applied to strings that originate in an exception or a policy message, where
    the author was writing for an operator reading a terminal and did not have a
    remote dashboard in mind.
    """
    if text is None:
        return None
    cleaned = _URL.sub("<endpoint>", text)
    cleaned = _APPROVAL.sub("<approval>", cleaned)
    cleaned = _BEARER.sub("<credential>", cleaned)
    cleaned = _HIGH_ENTROPY.sub("<redacted>", cleaned)
    if len(cleaned) > MAX_TEXT:
        cleaned = cleaned[:MAX_TEXT] + f"… (+{len(cleaned) - MAX_TEXT} chars)"
    return cleaned


def _envelope(kind: str, dropped: list[str], **payload: Any) -> dict[str, Any]:
    return {
        "schema_version": PUBLISH_SCHEMA_VERSION,
        "kind": kind,
        **payload,
        "redaction": {"policy": PUBLISH_POLICY, "dropped": dropped},
    }


def _attributes(attrs: dict[str, Any]) -> dict[str, Any]:
    """Keep the shape of a free-form map, drop the values it was not vetted for."""
    return {
        key: (attrs[key] if key in SAFE_ATTRIBUTE_KEYS else "<redacted>")
        for key in sorted(attrs)
    }


# -- run ---------------------------------------------------------------------


def _run_body(run: Run) -> dict[str, Any]:
    verdict = run.verdict
    return {
        "run_id": run.run_id,
        "scenario_id": run.scenario_id,
        "target_id": run.target_id,
        "profile": run.profile,
        "status": str(run.status),
        "dry_run": run.dry_run,
        "created_at": run.created_at.isoformat(),
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "scenario_digest": run.scenario_digest,
        # The token itself is a credential; whether one was presented is the
        # fact a reviewer actually needs.
        "approved": run.approval_id is not None,
        "initiated_by": pseudonym("actor", run.initiated_by),
        "refusal_reason": scrub(run.refusal_reason),
        "execution": None
        if run.execution is None
        else {
            "executor": run.execution.executor,
            "ok": run.execution.ok,
            "started_at": run.execution.started_at.isoformat(),
            "finished_at": run.execution.finished_at.isoformat(),
            "steps_completed": list(run.execution.steps_completed),
            "error": scrub(run.execution.error),
        },
        "verdict": None
        if verdict is None
        else {
            "purple_verdict": str(verdict.purple_verdict),
            "prevention": str(verdict.prevention),
            "detection": str(verdict.detection),
            "evidence": str(verdict.evidence),
            "response": str(verdict.response),
            "rationale": scrub(verdict.rationale),
            "axes": [
                {
                    "axis": axis.axis,
                    "status": str(axis.status),
                    "summary": scrub(axis.summary),
                    "checks": [
                        {
                            "id": check.id,
                            "axis": check.axis,
                            "status": str(check.status),
                            "assertion": scrub(check.assertion),
                            "observed": scrub(check.observed),
                            "reason": scrub(check.reason),
                        }
                        for check in axis.checks
                    ],
                }
                for axis in verdict.axes
            ],
        },
    }


_RUN_DROPPED = [
    "evidence_ref",
    "execution.raw_ref",
    "approval_id",
    "initiated_by (pseudonymised)",
]


def publish_run(run: Run) -> dict[str, Any]:
    return _envelope("run", _RUN_DROPPED, run=_run_body(run))


def publish_runs(runs: list[Run]) -> dict[str, Any]:
    return _envelope("runs", _RUN_DROPPED, count=len(runs), runs=[_run_body(r) for r in runs])


# -- evidence ----------------------------------------------------------------

_EVIDENCE_DROPPED = [
    "sources.transcript.turns[].content",
    "sources.transcript.turns[].principal (pseudonymised)",
    "sources.otel.spans[].attributes[] values (except the safe-key allowlist)",
    "sources.otel.spans[].trace_id",
    "sources.otel.spans[].span_id",
    "sources.wazuh.alerts[].fields[] values",
    "sources.wazuh.alerts[].agent_name",
    "sources.tool_audit.records[].principal (pseudonymised)",
    "sources.tool_audit.records[].tenant_id (pseudonymised)",
    "sources.state_diff.changes[].keys[] values",
    "sources.*.meta.backend",
    "sources.*.meta.query",
]


def publish_evidence(bundle: dict[str, Any]) -> dict[str, Any]:
    """Project a stored evidence bundle into something safe to publish.

    Parsed through :class:`Evidence` first, whose models forbid extra fields, so
    a bundle carrying something this projection has never seen raises instead of
    flowing through unexamined.
    """
    evidence = Evidence.model_validate(bundle)
    src = evidence.sources

    transcript = None
    if src.transcript is not None:
        transcript = {
            "turn_count": len(src.transcript.turns),
            "turns": [
                {
                    "role": turn.role,
                    "step_id": turn.step_id,
                    "principal": pseudonym("principal", turn.principal),
                    "timestamp": turn.timestamp.isoformat() if turn.timestamp else None,
                    # A digest still answers "did the same text appear twice",
                    # which is most of what a transcript is used for here.
                    "content_digest": digest(turn.content),
                    "content_chars": len(turn.content),
                }
                for turn in src.transcript.turns
            ],
        }

    otel = None
    if src.otel is not None:
        otel = {
            "span_count": len(src.otel.spans),
            "trace_count": len(src.otel.trace_ids),
            "spans": [
                {
                    "name": span.name,
                    "status": span.status,
                    "start_time": span.start_time.isoformat() if span.start_time else None,
                    "end_time": span.end_time.isoformat() if span.end_time else None,
                    "attributes": _attributes(span.attributes),
                }
                for span in src.otel.spans
            ],
        }

    wazuh = None
    if src.wazuh is not None:
        wazuh = {
            "alert_count": len(src.wazuh.alerts),
            "alerts": [
                {
                    "rule_id": alert.rule_id,
                    "rule_level": alert.rule_level,
                    "rule_groups": list(alert.rule_groups),
                    # Operator-authored in the ruleset, not agent output.
                    "rule_description": scrub(alert.rule_description),
                    "timestamp": alert.timestamp.isoformat(),
                    "fields": _attributes(alert.fields),
                }
                for alert in src.wazuh.alerts
            ],
        }

    tool_audit = None
    if src.tool_audit is not None:
        tool_audit = {
            "record_count": len(src.tool_audit.records),
            "records": [
                {
                    "tool": record.tool,
                    "decision": record.decision,
                    "policy": record.policy,
                    "timestamp": record.timestamp.isoformat() if record.timestamp else None,
                    "principal": pseudonym("principal", record.principal),
                    "tenant": pseudonym("tenant", record.tenant_id),
                    # Already a digest upstream; republished as-is.
                    "arguments_digest": record.arguments_digest,
                }
                for record in src.tool_audit.records
            ],
        }

    state_diff = None
    if src.state_diff is not None:
        state_diff = {
            "change_count": len(src.state_diff.changes),
            "changes": [
                {
                    "collection": change.collection,
                    "operation": change.operation,
                    "count": change.count,
                    "key_names": sorted(change.keys),
                }
                for change in src.state_diff.changes
            ],
        }

    return _envelope(
        "evidence",
        _EVIDENCE_DROPPED,
        run_id=evidence.run_id,
        collected_at=evidence.collected_at.isoformat(),
        window=None
        if evidence.window is None
        else {
            "start": evidence.window.start.isoformat(),
            "end": evidence.window.end.isoformat(),
        },
        sources={
            "transcript": transcript,
            "otel": otel,
            "wazuh": wazuh,
            "tool_audit": tool_audit,
            "state_diff": state_diff,
        },
        collector_errors=[
            {"source": err.source, "fatal": err.fatal, "message": scrub(err.message)}
            for err in evidence.collector_errors
        ],
    )


# -- findings, coverage, audit -----------------------------------------------


def publish_posture(document: dict[str, Any] | None) -> dict[str, Any]:
    """Project the static-posture plane (issue #25).

    Embedded directly in ``static_posture``, the same as ``skill_assurance`` —
    not wrapped in the standalone-resource envelope, so the composed dashboard
    stays a flat, schema-checked shape rather than an envelope inside an
    envelope. ``StaticPostureFinding`` never captures the matched snippet in
    the first place (see ``models/posture.py``), so there is nothing further
    to strip from a finding beyond capping its scanner-authored title: rule
    id, severity, category, file path and coverage state pass through
    unchanged. Optional keys are omitted rather than sent as ``null``, so a
    status of ``not_tested`` does not carry an empty ``findings: []`` a reader
    could mistake for "scanned, nothing found".
    """
    document = document or {"status": "not_tested", "reason": "no_report"}
    body: dict[str, Any] = {"status": document.get("status", "not_tested")}
    if document.get("reason") is not None:
        body["reason"] = document["reason"]
    if document.get("detail") is not None:
        body["detail"] = scrub(document["detail"])
    if document.get("source_tool") is not None:
        body["source_tool"] = document["source_tool"]
    if document.get("source_version") is not None:
        body["source_version"] = document["source_version"]
    if "counts" in document:
        body["counts"] = dict(document["counts"])
    if document.get("problems"):
        body["problems"] = [
            {
                "rule_id": p.get("rule_id"),
                "file": p.get("file"),
                "detail": scrub(p.get("detail")),
            }
            for p in document["problems"]
        ]
    if "findings" in document:
        body["findings"] = [
            {
                "rule_id": f.get("rule_id"),
                "severity": f.get("severity"),
                "category": f.get("category"),
                "file": f.get("file"),
                "title": scrub(f.get("title")),
                "source_tool": f.get("source_tool"),
                "coverage": f.get("coverage"),
                "scenario_ids": list(f.get("scenario_ids") or []),
            }
            for f in document["findings"]
        ]
    return body


def publish_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Findings are workflow records: ids, statuses and operator-written notes."""
    return _envelope(
        "findings",
        ["owner (pseudonymised)"],
        count=len(findings),
        findings=[
            {
                "finding_id": f.get("finding_id"),
                "scenario_id": f.get("scenario_id"),
                "target_id": f.get("target_id"),
                "title": scrub(f.get("title")),
                "severity": f.get("severity"),
                "verdict": f.get("verdict"),
                "status": f.get("status"),
                "first_seen_run": f.get("first_seen_run"),
                "last_seen_run": f.get("last_seen_run"),
                "created_at": f.get("created_at"),
                "updated_at": f.get("updated_at"),
                "failed_axes": f.get("failed_axes") or [],
                "failed_checks": f.get("failed_checks") or [],
                "has_regression_test": bool(f.get("regression_test_ref")),
                "has_detection_rule": bool(f.get("detection_rule_ref")),
                "owner": pseudonym("owner", f.get("owner")),
                "notes": scrub(f.get("notes")),
            }
            for f in findings
        ],
    )


def publish_coverage(coverage: dict[str, Any]) -> dict[str, Any]:
    """Counts and category ids, all of it derived from the committed catalogue."""
    return _envelope(
        "coverage",
        [],
        **{
            key: value
            for key, value in coverage.items()
            if key != "load_errors"
        },
        load_errors=[scrub(str(e)) for e in coverage.get("load_errors") or []],
    )


def publish_audit(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Who did what, with 'who' pseudonymised and the free-form detail dropped.

    ``detail`` is written by whichever call site raised, holds no schema, and is
    the field most likely to carry an argument value. Its keys are published so a
    reader can see that a refusal recorded a reason; the values are not.
    """
    return _envelope(
        "audit",
        ["actor (pseudonymised)", "detail[] values"],
        count=len(rows),
        entries=[
            {
                "at": row.get("at"),
                "actor": pseudonym("actor", row.get("actor")),
                "action": row.get("action"),
                "subject": row.get("subject"),
                "outcome": row.get("outcome"),
                "detail_keys": sorted(_detail_keys(row.get("detail"))),
            }
            for row in rows
        ],
    )


def _detail_keys(detail: Any) -> list[str]:
    if isinstance(detail, str):
        import json

        try:
            detail = json.loads(detail)
        except ValueError:
            return ["<unparsed>"]
    if isinstance(detail, dict):
        return [str(k) for k in detail]
    return []


# -- declared configuration --------------------------------------------------


def publish_declared(payload: Any) -> dict[str, Any]:
    """Pass-through for reviewed configuration.

    Targets and scenarios are written by an operator, reviewed like firewall
    rules, and already stripped of endpoints and credential names by
    ``Target.redacted()``. They are not observations, so there is nothing here
    the system under test could have influenced.
    """
    return _envelope("declared", [], data=payload)


def publish_report(report: dict[str, Any]) -> dict[str, Any]:
    """The normalised batch rollup.

    ``normalize_batch`` is already the one shape every output renders from, and
    it stamps its own version. Republishing it is a no-op by design: if the
    rollup ever needs projecting, that is a sign it has started carrying
    observations rather than verdicts, and the fix belongs there.
    """
    return {"schema_version": PUBLISH_SCHEMA_VERSION, **report}


@lru_cache(maxsize=1)
def _dashboard_validator() -> Draft202012Validator:
    """The composite schema, with the purple rollup resolvable by ``$id``."""
    from agentsec.config import package_schema_dir

    schemas = package_schema_dir()
    rollup = json.loads((schemas / "dashboard.schema.json").read_text(encoding="utf-8"))
    composite = json.loads(
        (schemas / "project-dashboard.schema.json").read_text(encoding="utf-8")
    )
    registry = Registry().with_resource(rollup["$id"], Resource.from_contents(rollup))
    return Draft202012Validator(composite, registry=registry)


def publish_dashboard(document: dict[str, Any]) -> dict[str, Any]:
    """The composed project dashboard, projected and then checked against its schema.

    Three planes, named one at a time. Naming them is what keeps a fourth from
    appearing on a dashboard because someone added it to the service — the same
    reason every other publisher here lists its fields instead of filtering.

    The schema check is the second half. A consumer pins to
    ``project-dashboard.schema.json``, so serving a document that does not match
    it breaks that consumer in a way no test of ours would catch; refusing to
    serve is the failure they can see. It also means the purple plane is checked
    against the rollup contract on every read, which is where a field that
    quietly changed type would otherwise slip through.
    """
    body = {
        "schema_version": PUBLISH_SCHEMA_VERSION,
        "kind": "dashboard",
        "generated_at": document.get("generated_at"),
        "project": document.get("project"),
        # Already the one shape every output renders from, and it stamps its own
        # version. Republishing it is a no-op by design; see publish_report.
        "purple": document.get("purple"),
        "skill_assurance": document.get("skill_assurance"),
        # A fourth plane, composed beside the other three and never merged into
        # any of them (issue #25). Its own publisher, because unlike the other
        # two it names files and needs its own (already-minimal) redaction.
        "static_posture": publish_posture(document.get("static_posture")),
        "redaction": {"policy": PUBLISH_POLICY, "dropped": []},
    }
    errors = sorted(_dashboard_validator().iter_errors(body), key=str)
    if errors:
        detail = "; ".join(
            f"{'/'.join(str(p) for p in e.absolute_path) or '(root)'}: {e.message}"
            for e in errors[:5]
        )
        raise PublicationInvalid(
            f"dashboard does not match its published schema: {detail}",
            details={"schema": "project-dashboard.schema.json"},
        )
    return body


PUBLISHERS: dict[str, Callable[[Any], dict[str, Any]]] = {
    "run": publish_run,
    "runs": publish_runs,
    "evidence": publish_evidence,
    "findings": publish_findings,
    "coverage": publish_coverage,
    "audit": publish_audit,
    "declared": publish_declared,
    "report": publish_report,
    "dashboard": publish_dashboard,
    "posture": publish_posture,
}


def publish(kind: str, value: Any) -> dict[str, Any]:
    """Project ``value`` for publication, or refuse.

    Refusing is the point. An output type nobody has written a policy for is one
    nobody has decided is safe to publish, and defaulting to "send it" is how a
    transcript ends up on a dashboard.
    """
    publisher = PUBLISHERS.get(kind)
    if publisher is None:
        raise RedactionError(
            f"no publication policy for output kind '{kind}'",
            details={"known": sorted(PUBLISHERS)},
        )
    return publisher(value)
