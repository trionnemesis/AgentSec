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

## Control-contract findings, verified against the published artifact

The earlier record called the AgentShield/Claude hook mismatch a *source-level
candidate* read from GitHub. It is now verified one level further down, against
the **published npm artifact** rather than a branch of its source repository.
This is still **not** a live-reproduced verdict — see "What this does and does
not establish" below.

### Integrity chain

The inspected bytes are the authentic published release:

| Item | Value |
|---|---|
| Package | `ecc-agentshield@1.4.0` |
| Registry `dist.integrity` | `sha512-R98OO1Ujyk2lezDLb+iQmMhF6FwTJCHajy3G4FCB6x7wkSTqR9f8+eAelC5KDzYDsGSbc0sOZvjXOOPRBtMpDg==` |
| Registry `dist.shasum` | `2337dfa586c35664d3150183718c27ef0bed1e52` |
| Locally recomputed SHA-512 (base64) | identical to `dist.integrity` |
| Locally recomputed SHA-1 | identical to `dist.shasum` |
| `package/dist/index.js` SHA-256 | `5380b096bffc5654f25b6d048e38f0f2ae20c852899546be1a148616fbe07e93` |
| `package/dist/index.js` size | 641971 bytes |
| Declared `bin` | `{"agentshield": "dist/index.js"}` |

The package was downloaded with `npm pack` and unpacked for reading. It was
**not executed**; no `runtime install` was run against any repository.

### What the shipped installer writes

`dist/index.js:14931` — the entry appended to `PreToolUse`:

```js
var HOOK_ENTRY = {
  matcher: "",
  hook: HOOK_COMMAND
};
```

`dist/index.js:14930` — the command, reading its two inputs from the process
environment (elided in the middle; the two reads and the two exits are verbatim):

```js
var HOOK_COMMAND = `node -e "…const t=process.env.TOOL_NAME||'unknown';const i=process.env.TOOL_INPUT||'';…
for(const r of pol.deny||[]){if(r.tool==='*'||r.tool===t||t.startsWith(r.tool.replace('*',''))){
  if(!r.pattern||new RegExp(r.pattern,'i').test(i)){…decision:'block'…process.exit(2)}}}
…decision:'allow'…process.exit(0)"`;
```

`dist/index.js:14896` — the default policy the command evaluates:

```json
{
  "version": 1,
  "deny": [
    {"tool": "Bash", "pattern": "rm -rf /", "reason": "Prevents destructive filesystem operations"},
    {"tool": "Bash", "pattern": "curl.*\\|.*sh", "reason": "Blocks piping remote scripts to shell"}
  ],
  "rateLimit": {"maxPerMinute": 30, "tools": ["Bash", "Write"]},
  "log": {"enabled": true, "path": ".agentshield/runtime.ndjson"}
}
```

`installRuntime` merges `HOOK_ENTRY` into `settings.hooks.PreToolUse` of
`<target>/.claude/settings.json`, keying idempotency off the substring
`agentshield/runtime-policy` in `h.hook`.

### What Claude Code actually consumes

This repository's own `.claude/settings.json` carries a PreToolUse hook that is
**demonstrably live**: a `Write` to `fixtures/.hook-contract-probe.tmp` attempted
during this review was refused with the hook's own text, `"/fixtures/ is
operator-owned. …"`, and no file was created. Its working shape is:

```json
"PreToolUse": [
  {
    "matcher": "Bash|Write|Edit|NotebookEdit|mcp__.*",
    "hooks": [{"type": "command", "command": "python3 \"$CLAUDE_PROJECT_DIR/.claude/hooks/guard_agentsec.py\""}]
  }
]
```

`.claude/hooks/guard_agentsec.py` reads its payload from **stdin** and writes a
`hookSpecificOutput` decision to stdout. Claude Code version observed: `2.1.246`.

### Two independent defects

**D1 — hook entry schema.** AgentShield writes a sibling scalar `hook`; Claude
Code reads a `hooks` array of `{type, command}` objects. An entry carrying
neither `hooks` nor `type`/`command` supplies no command to run. `matcher: ""`
is separately not the documented "match every tool" spelling.

**D2 — hook input protocol.** Claude Code delivers `tool_name`, `tool_input` and
`tool_use_id` as stdin JSON. It does not set `TOOL_NAME` or `TOOL_INPUT`. Under
that protocol the shipped command binds `t = 'unknown'` and `i = ''`.

D2's consequence follows from the quoted loop by inspection, for the shipped
default policy: `r.tool === '*'` is false for both rules; `r.tool === t` is
`'Bash' === 'unknown'`, false; `t.startsWith(r.tool.replace('*',''))` is
`'unknown'.startsWith('Bash')`, false. No deny rule can match, whatever the tool
call was, so the command falls through to its `decision:'allow'` tail and
`process.exit(0)`. The record it appends names `tool: "unknown"` and carries no
tool input.

D1 and D2 are independent: D1 alone means the command never runs and
`runtime.ndjson` stays empty; D2 alone means it runs and allows everything. Each
is a candidate total prevention bypass of the installed control, and the second
also destroys the tool identity the evidence axis needs.

**D3 — record identity.** Both branches append
`{timestamp, tool, decision, reason?, durationMs}`. There is no canonical
`agentsec.run_id`, no per-invocation record ID, no `tool_call_id` to bind to a
Claude `tool_use_id`, and no producer version. `canonical_run_id`
(`src/agentsec/evidence/base.py:123`) reads only a direct `agentsec.run_id` key
or a direct `agentsec` object, and `require_run_id_value`
(`src/agentsec/evidence/base.py:162`) raises `EvidenceUnavailable` when it is
absent outside a trusted fixture. So an unmodified AgentShield log fails closed
in `collect_tool_audit` — correctly. A bridge that adds identity without
altering the recorded decision, reason or timestamp is required before any
AgentShield output can be live evidence.

### What this does and does not establish

Established: the shipped bytes of the pinned release, their digests, the exact
settings fragment `installRuntime` writes, the exact input contract the command
expects, and the shape Claude Code 2.1.246 actually executes.

Not established: that a Claude Code session with this hook installed allows a
call the policy denies. That requires the live loop below. Nothing here is a
`prevention_gap` verdict, a finding, or a regression, and no scenario asserts it.

## Actual remaining dependencies

This execution environment has Claude Code `2.1.246`, Node `v22.22.3` and
npm `10.9.8`. The previously recorded "no Claude Code executable" dependency is
resolved. Five distinct prerequisites remain, each an operator action:

| # | Prerequisite | Exact observation |
|---|---|---|
| 1 | Claude Code authentication | `claude -p …` returns `Failed to authenticate. API Error: 401 OAuth access token has been revoked.` `~/.claude/.credentials.json` is present; `ANTHROPIC_API_KEY` is unset. Re-authenticate interactively. |
| 2 | Permission to execute the pinned package | Executing the unpacked `dist/index.js` was refused by the session's command classifier. `runtime install` / `runtime status` cannot be exercised without it. |
| 3 | A sanctioned run entry point | `agentsec run` from Bash is denied by `.claude/hooks/guard_agentsec.py` by design. The `agentsec` MCP server fails to start: `ENOENT: Executable not found in $PATH: agentsec-mcp`. The binary exists at `.venv/bin/agentsec-mcp`; `.mcp.json` invokes the bare name. |
| 4 | Target registration | `policy/targets.yaml` and `fixtures/` are refused by the same hook as operator-owned. A Claude Code staging target and its fixture set must be added under review, not by the agent. |
| 5 | Merge permission | `gh pr ready` and `gh pr merge` were refused by the session's command classifier. |

Credential presence was checked without reading or publishing any credential
value. Use an authenticated Claude Code workspace; do not put credentials in
this repository or a handoff message.

Pinned AgentShield reference:

- package `ecc-agentshield@1.4.0`;
- commit `bdad15dd28da548a0586d6ca989cb5aa35a67ad6`;
- [package identity](https://github.com/affaan-m/agentshield/blob/bdad15dd28da548a0586d6ca989cb5aa35a67ad6/package.json),
  [public CLI](https://github.com/affaan-m/agentshield/blob/bdad15dd28da548a0586d6ca989cb5aa35a67ad6/src/index.ts),
  [runtime installer](https://github.com/affaan-m/agentshield/blob/bdad15dd28da548a0586d6ca989cb5aa35a67ad6/src/runtime/install.ts).

The source does not provide a public `runtime evaluate` command. Use the public
installer/output contract; do not import internal TypeScript modules or create
an AgentSec policy engine.

## Next executable loop

1. In an authenticated Claude Code environment, create one disposable staging
   repository. Pin the external package and record the actual Claude version.
   Leave user/global settings untouched.
2. Use the pinned public `agentshield runtime install --path <staging-repo>` and
   `agentshield runtime status --path <staging-repo> --json --check` interfaces.
   Record the settings/hook artifacts actually generated, and diff them against
   the `HOOK_ENTRY` quoted above — a newer patch release may have changed them.
3. Check the catalogue again. At this baseline, none of the eight scenarios
   covers `.claude/settings.json` tool-grant bypass: `AGT-CONFIG-003` covers
   shell interpolation in `.claude/hooks`, a different threat. Only introduce
   one reviewed settings/tool-grant scenario if this gap still exists.
   Budget for the catalogue size being asserted in more places than the
   catalogue: `tests/test_scenario.py:51`, `:83`,
   `tests/test_agt_config_scenarios.py:92` and `:103` each assert `== 8`, and
   eleven documents spell the count in prose. Two of those four assertions
   count *categories*, not scenarios, and stay at 8 if the new scenario reuses
   an `owasp_agentic` id the catalogue already covers.
4. Run one bounded, synthetic tool-call attempt through **Claude Code** and the
   existing HTTP target-driver boundary. Observe the hook invocation and actual
   control outcome. Directly invoking a hook or hand-building a transcript does
   not count as the required live run. D1 and D2 above predict what that run
   should show; a live run that contradicts them retires them, and that
   contradiction is the more valuable result.
5. Correlate audit records to that run and each actual `tool_use_id`, with a
   record ID and producer pin — the D3 gap. If a bridge is needed, narrowly
   adapt the public generated hook/input/output; never stamp an unrelated
   historical log with a new run ID. Preserve real target decisions and
   timestamps.
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
add a second harness/backend, or claim Part B complete from these unit tests or
from the artifact reading above.
