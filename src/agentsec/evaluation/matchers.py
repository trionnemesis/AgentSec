"""Shared matching primitives.

Every axis matches assertions against normalised evidence through these, so a
change to (say) how a Wazuh field comparison works applies identically to the
detection axis and the evidence axis.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from agentsec.models.evidence import (
    Evidence,
    OtelSpan,
    StateChange,
    ToolAuditRecord,
    WazuhAlert,
)
from agentsec.models.scenario import (
    AlertAssertion,
    SpanAssertion,
    StateChangeAssertion,
    ToolAuditAssertion,
)


def assistant_text(
    evidence: Evidence,
    *,
    in_step: str | None = None,
    as_principal: str | None = None,
) -> str:
    """Assistant output, optionally narrowed to one step or principal.

    Narrowing matters: an unscoped ``must_not: output_contains ORD-B-77421``
    would fire on a legitimate turn made *as* tenant B, reporting a cross-tenant
    leak that never happened.
    """
    transcript = evidence.sources.transcript
    if transcript is None:
        return ""
    turns = [t for t in transcript.turns if t.role == "assistant"]
    if in_step is not None:
        turns = [t for t in turns if t.step_id == in_step]
    if as_principal is not None:
        turns = [t for t in turns if t.principal == as_principal]
    return "\n".join(t.content for t in turns)


def tool_records(evidence: Evidence) -> list[ToolAuditRecord]:
    source = evidence.sources.tool_audit
    return list(source.records) if source else []


def spans(evidence: Evidence) -> list[OtelSpan]:
    source = evidence.sources.otel
    return list(source.spans) if source else []


def alerts(evidence: Evidence) -> list[WazuhAlert]:
    source = evidence.sources.wazuh
    return list(source.alerts) if source else []


def state_changes(evidence: Evidence) -> list[StateChange]:
    source = evidence.sources.state_diff
    return list(source.changes) if source else []


def text_contains(haystack: str, needle: str, *, case_sensitive: bool) -> bool:
    if case_sensitive:
        return needle in haystack
    return needle.casefold() in haystack.casefold()


def text_matches(haystack: str, pattern: str, *, case_sensitive: bool) -> bool:
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        return re.search(pattern, haystack, flags) is not None
    except re.error:
        # A broken regex in a contract must not silently mean "no match", which
        # would read as a pass on a must_not assertion.
        raise ValueError(f"invalid regex in contract: {pattern!r}") from None


def match_span(span: OtelSpan, assertion: SpanAssertion) -> bool:
    if span.name != assertion.name:
        return False
    if assertion.status is not None and span.status != assertion.status:
        return False
    for key, expected in assertion.attributes.items():
        if key not in span.attributes:
            return False
        if not _scalar_eq(span.attributes[key], expected):
            return False
    return True


def count_spans(evidence: Evidence, assertion: SpanAssertion) -> int:
    return sum(1 for s in spans(evidence) if match_span(s, assertion))


def match_alert(
    alert: WazuhAlert, assertion: AlertAssertion, *, window_start: datetime | None
) -> bool:
    if assertion.rule_id is not None and alert.rule_id != assertion.rule_id:
        return False
    if assertion.rule_group is not None and assertion.rule_group not in alert.rule_groups:
        return False
    if assertion.min_level is not None and (alert.rule_level or 0) < assertion.min_level:
        return False
    for key, expected in assertion.match_fields.items():
        if key not in alert.fields:
            return False
        if not _scalar_eq(alert.fields[key], expected):
            return False
    if window_start is not None:
        deadline = window_start + timedelta(seconds=assertion.within_seconds)
        ts = alert.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=window_start.tzinfo)
        # An alert that fires an hour later is a real alert but not a *timely*
        # one; detection latency is part of the contract.
        if ts > deadline:
            return False
    return True


def find_alerts(
    evidence: Evidence, assertion: AlertAssertion, *, window_start: datetime | None
) -> list[WazuhAlert]:
    return [a for a in alerts(evidence) if match_alert(a, assertion, window_start=window_start)]


def match_tool_record(record: ToolAuditRecord, assertion: ToolAuditAssertion) -> bool:
    if assertion.tool is not None and record.tool != assertion.tool:
        return False
    if assertion.decision is not None and record.decision != assertion.decision:
        return False
    return not (
        assertion.principal is not None and record.principal != assertion.principal
    )


def count_tool_records(evidence: Evidence, assertion: ToolAuditAssertion) -> int:
    return sum(1 for r in tool_records(evidence) if match_tool_record(r, assertion))


def match_state_change(change: StateChange, assertion: StateChangeAssertion) -> bool:
    if assertion.collection is not None and change.collection != assertion.collection:
        return False
    if assertion.operation is not None and change.operation != assertion.operation:
        return False
    for key, expected in assertion.selector.items():
        if key not in change.keys:
            return False
        if not _scalar_eq(change.keys[key], expected):
            return False
    return True


def find_state_changes(
    evidence: Evidence, assertion: StateChangeAssertion
) -> list[StateChange]:
    return [c for c in state_changes(evidence) if match_state_change(c, assertion)]


def _scalar_eq(observed: object, expected: object) -> bool:
    """Compare loosely across the string/number/bool boundary.

    Contracts are written in YAML by humans; ``rule.level: "10"`` and
    ``rule.level: 10`` mean the same thing to the person writing it, and a
    purple test that silently never matches because of a quote is worse than no
    test at all.
    """
    if observed == expected:
        return True
    if observed is None:
        return False
    if isinstance(expected, bool) or isinstance(observed, bool):
        return str(observed).lower() == str(expected).lower()
    return str(observed) == str(expected)
