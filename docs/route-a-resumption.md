# Route A resumption record

Baseline reviewed: `51df65934bb8a3fa2eb7956d616271cef21594c5` (`v0.4.3`).
Reviewed 2026-09-05. This is the user's Part B / WP-2 route, confirmed as
[#32 Stage 1 / Route A](https://github.com/trionnemesis/AgentSec/issues/32#issuecomment-5513171090).
It is **not complete**. No Claude Code live run or replay recording was produced
in this work environment.

## Reproduced and corrected prerequisites

1. [#77](https://github.com/trionnemesis/AgentSec/issues/77) has a separate
   provenance ADR/implementation change. Qualifying current-run file evidence
   must not be classified by its file transport. That change does not settle
   Route A's control-verification acceptance.
2. `collect_tool_audit` treated `.ndjson` as one JSON document. Two valid records
   failed with `Extra data: line 2`. `.ndjson` now uses the existing `.jsonl`
   reader. `tests/test_route_a_ndjson.py` reproduces the failure before the fix
   and verifies parity, unchanged timestamps, block-to-deny normalization and
   malformed/missing/foreign/conflicting run-ID rejection after it.

The parser test supplies synthetic records with explicit correlation. It is not
an AgentShield runtime recording. Accepting the extension alone does not enrich
AgentShield output or make it usable as live evidence.

## Actual remaining dependencies

This execution environment has Node/npm, but no Claude Code executable or
available Claude authentication. A real Claude Code staging run therefore
cannot be attempted here. Credential presence was checked without reading or
publishing any credential values. Use an authenticated Claude Code workspace;
do not put credentials in this repository or a handoff message.

Pinned AgentShield reference:

- package `ecc-agentshield@1.4.0`;
- commit `bdad15dd28da548a0586d6ca989cb5aa35a67ad6`;
- [package identity](https://github.com/affaan-m/agentshield/blob/bdad15dd28da548a0586d6ca989cb5aa35a67ad6/package.json),
  [public CLI](https://github.com/affaan-m/agentshield/blob/bdad15dd28da548a0586d6ca989cb5aa35a67ad6/src/index.ts),
  [runtime installer](https://github.com/affaan-m/agentshield/blob/bdad15dd28da548a0586d6ca989cb5aa35a67ad6/src/runtime/install.ts).

The pinned installer emits `{matcher: "", hook: "node -e ..."}` and reads
`TOOL_NAME` / `TOOL_INPUT` from the environment. The
[Claude Code hook reference](https://code.claude.com/docs/en/hooks) reviewed on
2026-09-05 instead specifies `hooks: [{type: "command", command: "..."}]` and
stdin JSON containing `tool_name`, `tool_input`, and `tool_use_id`. This is a
**source-level candidate compatibility gap**, not a live-reproduced verdict.
The installer's exit `2` block behavior does match the documented hook behavior.

The pinned runtime log has timestamp, tool, decision, optional reason and
durationMs. It lacks canonical `agentsec.run_id`, invocation/record IDs and
producer version. The source does not provide a public `runtime evaluate`
command. Use the public installer/output contract; do not import internal
TypeScript modules or create an AgentSec policy engine.

## Next executable loop

1. In an authenticated Claude Code environment, create one disposable staging
   repository. Pin the external package and record the actual Claude version.
   Leave user/global settings untouched.
2. Use the pinned public `agentshield runtime install --path <staging-repo>` and
   `agentshield runtime status --path <staging-repo> --json --check` interfaces.
   Record the settings/hook artifacts actually generated.
3. Check the catalogue again. At this baseline, none of the eight scenarios
   covers `.claude/settings.json` tool-grant bypass: `AGT-CONFIG-003` covers
   shell interpolation in `.claude/hooks`, a different threat. Only introduce
   one reviewed settings/tool-grant scenario if this gap still exists.
4. Run one bounded, synthetic tool-call attempt through **Claude Code** and the
   existing HTTP target-driver boundary. Observe the hook invocation and actual
   control outcome. Directly invoking a hook or hand-building a transcript does
   not count as the required live run.
5. Correlate audit records to that run and each actual `tool_use_id`, with a
   record ID and producer pin. If a bridge is needed, narrowly adapt the public
   generated hook/input/output; never stamp an unrelated historical log with a
   new run ID. Preserve real target decisions and timestamps.
6. Use one real detection source, OTel file export, as selected in the
   [latest handoff](https://github.com/trionnemesis/AgentSec/issues/32#issuecomment-5548903050).
   Export observations from the actual target control. A synthetic OTel file or
   an AgentSec-computed allow/deny result is not a blue-team detection system.
7. Capture one real `prevention_gap`, `detection_gap`, or `error`; fix only its
   demonstrated cause, then rerun the **same** reviewed scenario live. Save the
   reviewed, redacted replay evidence and its regression. Ensure cleanup runs
   on both success and failure.

Required completion evidence: external pins, scenario digest, before/after run
IDs, tool-call/audit correlation, OTel source, four axes, provenance with reason,
one defect/fix, replay regression and cleanup result. Response stays
`not_tested` absent an actual response event and SLA. Missing detection contract
means `not_tested`; an asserted but unavailable backend means `error`.

Stop when this single Route A loop is proven. Do not start ECC Memory Route B,
add a second harness/backend, or claim Part B complete from these unit tests.
