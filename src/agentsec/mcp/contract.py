"""The MCP tool and resource contract, as data.

Declaring the surface as data rather than as decorated functions buys two things:

1. ``tests/test_mcp_contract.py`` can assert architectural properties — no
   generic executor, no free-text URL, no raw SQL — as ordinary unit tests. A
   pull request that adds ``execute_shell`` fails CI, which is stronger than a
   note in a design doc.
2. The same definitions can be rendered into docs, or bound to a different
   protocol, without touching handler code.

Every tool is *narrow by construction*: callers name a target by id and the
service resolves endpoints, credentials and runners from the operator-owned
allowlist. A model cannot widen its own reach by choosing a different argument.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

RiskTier = Literal["read", "write", "execute"]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    title: str
    description: str
    risk: RiskTier
    input_schema: dict[str, Any]
    handler: str
    """Name of the HarnessService method this tool delegates to."""
    read_only: bool = True
    requires_confirmation: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "risk": self.risk,
            "read_only": self.read_only,
            "requires_confirmation": self.requires_confirmation,
            "input_schema": self.input_schema,
        }


@dataclass(frozen=True)
class ResourceSpec:
    uri_template: str
    title: str
    description: str
    handler: str
    publish: str
    """Publication policy in ``reporting.publish.PUBLISHERS``.

    Required, and validated at startup: a resource whose output has no policy
    stops the gateway from booting rather than serving a raw model. There is no
    default because a default is a decision that nobody made.
    """
    published: bool = True
    """Served by the read-only report gateway.

    ``AGENTSEC_MCP_READ_ONLY=1`` is the deployment where something outside the
    security team — a dashboard, a Live Artifact — is the reader. Everything is
    a read, so read-only is not the question; the question is whether this URI
    is a *product* for that reader or an internal working surface. Authoring
    detail, per-run evidence and the audit log are the latter.
    """
    mime_type: str = "application/json"


def _obj(
    properties: dict[str, Any],
    required: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        # No caller may invent a parameter. Combined with the absence of any
        # free-text endpoint field, this is what keeps the blast radius equal to
        # the allowlist rather than to the network.
        "additionalProperties": False,
    }


_TARGET_ID = {
    "type": "string",
    "pattern": "^[a-z0-9][a-z0-9-]{2,63}$",
    "description": "Allowlisted target id. Endpoints and credentials are resolved "
                   "server-side; there is no way to pass a URL.",
}
_SCENARIO_IDS = {
    "type": "array",
    "items": {"type": "string", "pattern": "^AGT-[A-Z0-9]+-[0-9]{3}$"},
    "maxItems": 50,
    "description": "Scenario ids from the catalogue. Omit to use the profile's set.",
}
_PROFILE = {
    "type": "string",
    "enum": ["pr", "nightly", "release"],
    "default": "pr",
}
#: Reporting has no sensible default profile: a report filtered to `pr` but headed
#: with a profile the caller never chose is the mislabelling this field exists to
#: avoid. Omitting it reports across every profile, and the report says so.
_REPORT_PROFILE = {
    "type": "string",
    "enum": ["pr", "nightly", "release"],
    "description": "Restrict the report to one profile. Omit to report across all of them.",
}


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="agentsec_list_targets",
        title="List targets",
        description=(
            "List allowlisted purple-team targets with their capabilities, risk "
            "ceiling and configured evidence backends. Endpoints and credential "
            "names are withheld."
        ),
        risk="read",
        input_schema=_obj({}),
        handler="list_targets",
    ),
    ToolSpec(
        name="agentsec_get_target_schema",
        title="Describe a target",
        description=(
            "Everything needed to author a scenario against one target: declared "
            "capabilities, logical principal names, available executors, evidence "
            "backends and already-applicable scenarios."
        ),
        risk="read",
        input_schema=_obj({"target_id": _TARGET_ID}, ["target_id"]),
        handler="get_target_schema",
    ),
    ToolSpec(
        name="agentsec_validate_scenario",
        title="Validate a scenario",
        description=(
            "Validate a catalogued scenario or an inline draft against the schema, "
            "the semantic rules and (optionally) a target. Use this before "
            "proposing a scenario for commit. Returns errors and warnings; a "
            "warning such as 'red_only' means the scenario tests attack success "
            "but not detection."
        ),
        risk="read",
        input_schema=_obj(
            {
                "scenario_id": {"type": "string", "pattern": "^AGT-[A-Z0-9]+-[0-9]{3}$"},
                "scenario_body": {
                    "type": "object",
                    "description": "Inline scenario document, for validating a draft "
                                   "that is not yet committed.",
                },
                "target_id": _TARGET_ID,
            }
        ),
        handler="validate_scenario",
    ),
    ToolSpec(
        name="agentsec_preview_run",
        title="Preview a run",
        description=(
            "Show exactly what would execute — scenarios, attack steps, evidence "
            "sources, policy decision, which scenarios need approval and which "
            "would block CI — without running anything. Always preview before "
            "starting a run."
        ),
        risk="read",
        input_schema=_obj(
            {
                "target_id": _TARGET_ID,
                "scenario_ids": _SCENARIO_IDS,
                "profile": _PROFILE,
            },
            ["target_id"],
        ),
        handler="preview_run",
    ),
    ToolSpec(
        name="agentsec_start_run",
        title="Start a run",
        description=(
            "Execute the selected scenarios against an allowlisted target and "
            "return the purple verdicts. Preview first — that is a convention, not "
            "an enforced precondition. High-risk and destructive scenarios do require "
            "an approval token, granted out of band by a human: no tool mints one."
        ),
        risk="execute",
        input_schema=_obj(
            {
                "target_id": _TARGET_ID,
                "scenario_ids": _SCENARIO_IDS,
                "profile": _PROFILE,
                "dry_run": {
                    "type": "boolean",
                    "default": False,
                    "description": "Evaluate policy and record the run without executing.",
                },
                "approval_id": {
                    "type": "string",
                    "pattern": "^apr_[0-9a-f]{16}$",
                    "description": "Approval token for scenarios that require one.",
                },
            },
            ["target_id"],
        ),
        handler="start_run",
        read_only=False,
        requires_confirmation=True,
    ),
    ToolSpec(
        name="agentsec_get_run",
        title="Get a run",
        description="Fetch one run: status, purple verdict, per-axis results and failed checks.",
        risk="read",
        input_schema=_obj(
            {"run_id": {"type": "string", "pattern": "^RUN-[0-9]{8}-[0-9]{3}$"}},
            ["run_id"],
        ),
        handler="get_run",
    ),
    ToolSpec(
        name="agentsec_compare_runs",
        title="Compare two runs",
        description=(
            "Diff two runs check-by-check to separate real regressions from "
            "contract edits. Reports contract_changed when the two runs used "
            "different scenario contracts, in which case a verdict difference "
            "says nothing about the system under test."
        ),
        risk="read",
        input_schema=_obj(
            {
                "run_a": {"type": "string", "pattern": "^RUN-[0-9]{8}-[0-9]{3}$"},
                "run_b": {"type": "string", "pattern": "^RUN-[0-9]{8}-[0-9]{3}$"},
            },
            ["run_a", "run_b"],
        ),
        handler="compare_runs",
    ),
    ToolSpec(
        name="agentsec_promote_finding",
        title="Advance a finding",
        description=(
            "Move a finding along its workflow (new -> reproduced -> fixing -> "
            "regression_added -> detection_added -> verified -> closed). A finding "
            "cannot reach 'verified' without a linked regression test, and a "
            "detection gap additionally needs a linked detection rule."
        ),
        risk="write",
        input_schema=_obj(
            {
                "finding_id": {"type": "string", "pattern": "^FND-[0-9]{8}-[0-9]{3}$"},
                "status": {
                    "type": "string",
                    "enum": [
                        "reproduced", "fixing", "regression_added", "detection_added",
                        "verified", "closed", "accepted_risk",
                    ],
                },
                "regression_test_ref": {"type": "string", "maxLength": 400},
                "detection_rule_ref": {"type": "string", "maxLength": 400},
                "note": {"type": "string", "maxLength": 2000},
            },
            ["finding_id", "status"],
        ),
        handler="promote_finding",
        read_only=False,
    ),
    ToolSpec(
        name="agentsec_validate_detection",
        title="Validate detection wiring",
        description=(
            "Check that a scenario's detection expectations are actually checkable "
            "against a target — backends configured, rule ids specified — without "
            "running an attack. Use this first when a detection gap looks "
            "suspicious: most are configuration, not blindness."
        ),
        risk="read",
        input_schema=_obj(
            {
                "scenario_id": {"type": "string", "pattern": "^AGT-[A-Z0-9]+-[0-9]{3}$"},
                "target_id": _TARGET_ID,
            },
            ["scenario_id", "target_id"],
        ),
        handler="validate_detection",
    ),
    ToolSpec(
        name="agentsec_create_regression_draft",
        title="Draft a regression scenario",
        description=(
            "Generate a blocking regression scenario pinned to a finding. Returns "
            "YAML text for review — it is deliberately not written to the "
            "catalogue, because adding a merge gate is a code-review event."
        ),
        risk="read",
        input_schema=_obj(
            {"finding_id": {"type": "string", "pattern": "^FND-[0-9]{8}-[0-9]{3}$"}},
            ["finding_id"],
        ),
        handler="create_regression_draft",
    ),
    ToolSpec(
        name="agentsec_generate_report",
        title="Generate a report",
        description=(
            "Render recent runs as a self-contained HTML report, JSON, and/or "
            "JUnit XML, and return the written paths plus a summary."
        ),
        risk="write",
        input_schema=_obj(
            {
                "target_id": _TARGET_ID,
                "profile": _REPORT_PROFILE,
                "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
                "formats": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["html", "json", "junit"]},
                    "default": ["html", "json"],
                },
            }
        ),
        handler="generate_report",
        read_only=False,
    ),
)


RESOURCES: tuple[ResourceSpec, ...] = (
    ResourceSpec(
        uri_template="agentsec://targets",
        title="Targets",
        description="Allowlisted targets, redacted.",
        handler="list_targets",
        publish="declared",
    ),
    ResourceSpec(
        uri_template="agentsec://targets/{target_id}",
        title="Target detail",
        description="One target's authoring schema.",
        handler="get_target_schema",
        publish="declared",
        # Logical principal names, permitted executors and declared capabilities
        # are what a scenario author needs and what a reader of the dashboard
        # does not: together they describe where the target can be pushed.
        published=False,
    ),
    ResourceSpec(
        uri_template="agentsec://scenarios",
        title="Scenarios",
        description="Scenario catalogue with tested axes and gate settings.",
        handler="list_scenarios",
        publish="declared",
    ),
    ResourceSpec(
        uri_template="agentsec://runs/{run_id}",
        title="Run",
        description="One run's verdict and per-axis results.",
        handler="get_run",
        publish="run",
    ),
    ResourceSpec(
        uri_template="agentsec://runs/{run_id}/evidence",
        title="Run evidence",
        description=(
            "The evidence bundle behind a verdict, projected for publication: "
            "transcript turns are reduced to digests and principals to stable "
            "pseudonyms. Raw bundles stay on the execution host."
        ),
        handler="get_run_evidence",
        publish="evidence",
        # Even projected, this is the investigator's surface rather than the
        # reader's, and it is the one place where a projection bug would be
        # worst. The report gateway does not offer it at all.
        published=False,
    ),
    ResourceSpec(
        uri_template="agentsec://project/risks",
        title="Repository risk plane",
        description=(
            "Whether this repository implements an AI agent and in what framework "
            "(`project.fingerprint`), and its own agent attack surface — skills, "
            "agents, hooks, tool grants, MCP servers, memory stores — read by the "
            "static rules in `agentsec.inspect` and triaged against the scenario "
            "catalogue. Each risk says whether a deterministic conclusion is "
            "available, obtainable, or out of reach. Not a verdict: nothing here has "
            "executed anything, so a repository with no runtime agent reads as "
            "`not_detected` rather than as a pass. Takes no arguments — which "
            "repository is a process-boundary decision (ADR 0003)."
        ),
        handler="inspect_repository",
        publish="repo_risk_document",
    ),
    ResourceSpec(
        uri_template="agentsec://findings",
        title="Findings",
        description="Findings and their workflow state.",
        handler="list_findings",
        publish="findings",
    ),
    ResourceSpec(
        uri_template="agentsec://dashboard/latest",
        title="Project dashboard",
        description=(
            "The latest state of this project as one document: identity and "
            "runtime-agent classification, the repository risk plane, the "
            "four-axis purple rollup, the Skill Assurance summary and ingested "
            "static posture, each in its own property and never merged. Computed "
            "in memory — reading it starts no run and writes no file. Schema: "
            "schemas/project-dashboard.schema.json."
        ),
        handler="dashboard",
        publish="dashboard",
    ),
    ResourceSpec(
        uri_template="agentsec://coverage",
        title="Coverage",
        description="OWASP Agentic Top 10 coverage and latest verdict histogram.",
        handler="coverage",
        publish="coverage",
    ),
    ResourceSpec(
        uri_template="agentsec://audit",
        title="Audit log",
        description="Recent gateway and CLI actions, including refusals.",
        handler="audit_tail",
        publish="audit",
        # The audit log is the record of who reached for what, including the
        # refusals. It belongs to the operators of the harness, not to its
        # readership.
        published=False,
    ),
)


def published_resources() -> tuple[ResourceSpec, ...]:
    """The read-only report gateway's resource allowlist."""
    return tuple(r for r in RESOURCES if r.published)


#: Tool names that must never exist on this server. Enforced by a unit test.
#: Each of these hands the model a general-purpose capability, at which point the
#: allowlist, the approval flow and the audit log all become decorative.
FORBIDDEN_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "execute_shell",
        "run_command",
        "query_database",
        "sql",
        "call_any_url",
        "http_request",
        "fetch",
        "run_arbitrary_prompt",
        "eval",
        "modify_wazuh_rule",
        "write_file",
        "read_file",
        "patch_target",
    }
)

#: Parameter names that must not appear in any tool's input schema. A tool that
#: accepts a URL or a SQL string is the generic tool above wearing a hat.
FORBIDDEN_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "url",
        "endpoint",
        "base_url",
        "host",
        "port",
        "command",
        "cmd",
        "shell",
        "sql",
        "query",
        "script",
        "code",
        "path",
        "file_path",
        "token",
        "password",
        "secret",
        "api_key",
        "credential",
        "headers",
    }
)


def tool_by_name(name: str) -> ToolSpec:
    for tool in TOOLS:
        if tool.name == name:
            return tool
    raise KeyError(name)


def contract_summary() -> dict[str, Any]:
    """Machine-readable description of the surface, for docs and diagnostics."""
    return {
        "tools": [t.to_dict() for t in TOOLS],
        "resources": [
            {
                "uri": r.uri_template,
                "title": r.title,
                "description": r.description,
                "publish": r.publish,
                "published": r.published,
            }
            for r in RESOURCES
        ],
        "counts": {
            "tools": len(TOOLS),
            "read_only_tools": sum(1 for t in TOOLS if t.read_only),
            "execute_tools": sum(1 for t in TOOLS if t.risk == "execute"),
            "resources": len(RESOURCES),
            "published_resources": len(published_resources()),
        },
    }
