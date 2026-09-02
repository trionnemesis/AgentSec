"""MCP prompts — the standard purple-team workflows.

A prompt teaches the client *how to use the tools*. It never carries a security
control: a model that ignores the prompt still cannot reach past the allowlist,
because the constraint lives in the tool schema and the policy guard, not here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PromptSpec:
    name: str
    title: str
    description: str
    template: str


CREATE_SCENARIO = PromptSpec(
    name="agentsec-create-scenario",
    title="Create a purple-team scenario",
    description="Turn a repository and a threat idea into a validated Attack-Detection Contract.",
    template="""\
Author an AgentSec scenario for target `{target_id}` covering: {threat}

Work in this order and do not skip ahead:

1. Call `agentsec_get_target_schema` for `{target_id}`. Note its declared
   capabilities, logical principal names, and which evidence backends exist.
   You cannot assert on a backend the target does not have.

2. Read the repository to find the agent's tools, its authorisation checks, and
   where tenant or user identity is enforced. Name the specific function or
   middleware you expect to hold the line.

3. Write the contract with all four axes in mind:
   - prevention: what must the agent refuse to do?
   - detection: which Wazuh rule must fire, and within how many seconds?
   - evidence: which OTel span or audit record proves the decision was made by
     policy rather than by luck?
   - response: leave `mode: not_tested` unless a real runbook or automation
     exists. Do not claim response coverage you do not have.

4. Call `agentsec_validate_scenario` with the draft body and `{target_id}`.
   Fix every error. Treat a `red_only` warning as an error: a scenario that
   checks only prevention cannot tell a fix from a silent bypass.

5. Present the YAML for review. Do not call `agentsec_start_run` yet.

Report: the contract, which code path you expect to enforce it, and which Wazuh
rule id must exist for the detection axis to be checkable.
""",
)

INVESTIGATE_FINDING = PromptSpec(
    name="agentsec-investigate-finding",
    title="Investigate a finding",
    description="Root-cause a non-secure verdict and propose a fix plus a regression test.",
    template="""\
Investigate finding `{finding_id}`.

1. Read `agentsec://findings` and the finding's runs. Read
   `agentsec://runs/{{run_id}}/evidence` for the failing run.

2. Before assuming the control is broken, call `agentsec_validate_detection`
   for the scenario and target. A large share of detection gaps are missing
   backends or absent rule ids, not blindness.

3. Locate the responsible code. Quote the file and line where the check should
   have happened, and explain why it did not.

4. Read the prevention axis before choosing the smallest remediation:
   - `detection_gap` with prevention `pass`: the control held. Add the missing
     telemetry, mapping, rule or span; do not change an application control that
     held.
   - `detection_gap` with prevention `fail`: both sides failed. Fix the
     application or policy control and detection, retaining regression evidence
     for both.
   A pipeline `error` is a stop reason, not a security finding: repair the
   backend, schema, correlation or collector before drawing a conclusion.

5. Call `agentsec_create_regression_draft` and include the YAML in your write-up.

Do not mark anything verified. Only a passing run after the fix does that.
""",
)

PURPLE_REVIEW = PromptSpec(
    name="agentsec-purple-review",
    title="Purple review of a change",
    description="Assess whether a code change needs new or updated purple coverage.",
    template="""\
Review the current diff for purple-team impact.

1. Identify anything that changes the agent's attack surface: a new tool, a new
   data source, a changed authorisation check, a new external call, a change to
   memory or retrieval.

2. For each, read `agentsec://coverage` and `agentsec://scenarios` and say
   whether an existing scenario already covers it. Name the scenario id, or say
   plainly that nothing does.

3. Where coverage is missing, draft the scenario and validate it with
   `agentsec_validate_scenario`.

4. Where a change might have broken an existing control, call
   `agentsec_preview_run` for the affected scenarios and report what would run.

Output: a table of change -> covering scenario -> gap, then the drafts. Be
explicit about what you did not check.
""",
)

PROMOTE_REGRESSION = PromptSpec(
    name="agentsec-promote-regression",
    title="Promote a fix to a regression gate",
    description="Turn a verified fix into a blocking CI gate.",
    template="""\
Promote the fix for finding `{finding_id}` into a permanent gate.

1. Call `agentsec_create_regression_draft` for `{finding_id}`.
2. Confirm the draft reproduces the original failure *before* the fix and passes
   after it. A regression test that has never failed is not a regression test.
3. Set `gate: blocking` and include the `pr` profile only if the scenario is
   fast and non-destructive; otherwise nightly.
4. Call `agentsec_promote_finding` with `regression_added` and the test path.
   For a detection gap, also link the detection rule — the service will refuse
   `verified` without it.

Report the draft, the profile choice, and why.
""",
)

DETECTION_REVIEW = PromptSpec(
    name="agentsec-detection-review",
    title="Detection coverage review",
    description="Audit which attacks would be seen, not just which would be blocked.",
    template="""\
Audit detection coverage for target `{target_id}`.

1. Read `agentsec://coverage` for the OWASP Agentic Top 10 picture.
2. For every scenario applicable to `{target_id}`, call
   `agentsec_validate_detection`. Build a table: scenario, checkable, expected
   Wazuh rule ids, last detection result.
3. Call out two failure modes explicitly:
   - scenarios that pass prevention but assert no detection at all
   - `must_fire` assertions with no rule_id, which pass on any alert
4. Recommend the three highest-value detection rules to add, ranked by the
   severity of what currently goes unseen.

Do not start runs. This is a read-only audit.
""",
)


PROMPTS: tuple[PromptSpec, ...] = (
    CREATE_SCENARIO,
    INVESTIGATE_FINDING,
    PURPLE_REVIEW,
    PROMOTE_REGRESSION,
    DETECTION_REVIEW,
)
