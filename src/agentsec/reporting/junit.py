"""JUnit XML output.

One testcase per scenario run. Mapping choices, which matter for how a CI UI
reads the result:

* blocking non-secure verdict -> ``<failure>``
* non-blocking non-secure     -> passing testcase with a ``<system-out>`` note,
                                 so a warning-gated scenario does not go red
* verdict ``error``           -> ``<error>``, never ``<failure>``: the
                                 difference between "your control is broken" and
                                 "our harness could not tell" must survive into CI
* scenario skipped by policy  -> ``<skipped>``
"""

from __future__ import annotations

from xml.etree import ElementTree as ET

from agentsec.reporting.normalizer import RunSummary


def render_junit(summaries: list[RunSummary], *, suite_name: str = "agentsec") -> str:
    failures = sum(1 for s in summaries if s.blocking and s.verdict != "error")
    errors = sum(1 for s in summaries if s.verdict == "error")
    skipped = sum(1 for s in summaries if s.status == "refused")

    suite = ET.Element(
        "testsuite",
        {
            "name": suite_name,
            "tests": str(len(summaries)),
            "failures": str(failures),
            "errors": str(errors),
            "skipped": str(skipped),
            "time": f"{sum(s.duration_seconds for s in summaries):.3f}",
        },
    )

    # A CI gate that is entirely fixture-derived is worth knowing about in the
    # job log — the same fact the HTML dashboard banners.
    fixture_derived = bool(summaries) and all(
        s.provenance.evidence == "recorded" for s in summaries
    )
    props = ET.SubElement(suite, "properties")
    ET.SubElement(
        props, "property",
        {"name": "agentsec.fixture_derived", "value": str(fixture_derived).lower()},
    )
    for kind in ("recorded", "live", "mixed"):
        count = sum(1 for s in summaries if s.provenance.evidence == kind)
        ET.SubElement(
            props, "property",
            {"name": f"agentsec.provenance.{kind}", "value": str(count)},
        )

    for s in summaries:
        case = ET.SubElement(
            suite,
            "testcase",
            {
                "classname": f"{suite_name}.{s.target_id}",
                "name": f"{s.scenario_id} {s.scenario_title}",
                "time": f"{s.duration_seconds:.3f}",
            },
        )

        detail = _detail(s)

        if s.status == "refused":
            ET.SubElement(case, "skipped", {"message": s.rationale or "refused by policy"})
            continue

        if s.verdict == "error":
            node = ET.SubElement(
                case, "error", {"message": s.rationale or "evaluation error", "type": "error"}
            )
            node.text = detail
            continue

        if s.verdict == "secure":
            continue

        if s.blocking:
            node = ET.SubElement(
                case, "failure", {"message": f"{s.verdict}: {s.rationale}", "type": s.verdict}
            )
            node.text = detail
        else:
            out = ET.SubElement(case, "system-out")
            out.text = (
                f"NON-BLOCKING {s.verdict} (gate={s.gate})\n{s.rationale}\n\n{detail}"
            )

    ET.indent(suite, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(
        suite, encoding="unicode"
    )


def _detail(s: RunSummary) -> str:
    lines = [
        f"run_id:    {s.run_id}",
        f"scenario:  {s.scenario_id} ({s.severity})",
        f"target:    {s.target_id}",
        f"verdict:   {s.verdict}",
        f"axes:      prevention={s.prevention} detection={s.detection} "
        f"evidence={s.evidence} response={s.response}",
        f"provenance: executor={s.provenance.executor} adapter={s.provenance.adapter} "
        f"evidence={s.provenance.evidence}",
        "",
    ]
    if s.collector_errors:
        lines.append("collector errors:")
        lines += [f"  - {e['source']}: {e['message']}" for e in s.collector_errors]
        lines.append("")
    if s.failed_checks:
        lines.append("failed checks:")
        for c in s.failed_checks:
            lines.append(f"  [{c['axis']}] {c['assertion']}")
            lines.append(f"      observed: {c['observed']}")
            if c["reason"]:
                lines.append(f"      why it matters: {c['reason']}")
    return "\n".join(lines)
