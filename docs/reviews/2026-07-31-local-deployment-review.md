# Local deployment review — 2026-07-31

Reviewed at `ce4f986` on `main`. Python 3.11.15, clean virtualenv, no network to any
agent or SIEM. The MCP gateway was exercised with a real stdio client (`mcp` 1.29.0),
not a mock.

Interactive dashboard rendering this review:
<https://claude.ai/code/artifact/1bd63b3a-6a33-4303-9e8b-39a895ede90f>

> **Status:** all twelve findings are **fixed on this branch**, with regression tests.
> See "What was fixed" below. Two were resolved by correcting the documentation rather
> than the code — 07 and part of 08 — and each says why.

---

## Part 1 — deployment verification

| Step | Command | Result |
|---|---|---|
| Install from source | `pip install -e '.[dev,mcp]'` | clean |
| Lint / types / tests | `ruff check .` · `mypy` · `pytest -q` | clean · 49 files · **146 passed** |
| Validate the catalogue | `agentsec validate` | 0 errors, 0 warnings ×4 · exit 0 |
| Preview | `agentsec preview --target demo-agent-fixture` | exit 0 |
| Full pipeline | `agentsec_start_run` (MCP) | 2 secure, 1 `prevention_gap`, 1 `detection_gap` · exit 1 |
| Register the gateway | `claude mcp add agentsec -- agentsec-mcp` | `claude mcp list` → **✓ Connected** |
| Gateway surface | `tools/list`, `resources/list`, `prompts/list` | 11 tools · 5 resources + 3 templates · 5 prompts |
| Argument constraints | required / `pattern` / `enum` / `maxItems` | 4 / 4 refused server-side |
| Read-only mode | `AGENTSEC_MCP_READ_ONLY=1` | `start_run`, `promote_finding`, `generate_report` all refused at dispatch |
| Reports | `agentsec report --format html --format json --format junit` | all three written |

The offline result matches the README exactly, including the deliberate exit 1.

Two things a new user hits that the docs do not mention:

* The HTML report renders but is not yet a dashboard — no axis rollup, no filtering,
  no trend (finding 04).
* README §2 tells a new user to run `agentsec run …`, which is denied inside Claude
  Code by both `.claude/settings.json` and the guard hook, by design (finding 12).

---

## Part 2 — findings

Ranked by how badly each undermines the project's own central claim: an untested or
uncollectable axis must never round up to a pass.

### 01 · high · A target that names its tool-call span differently gets a free pass on the evidence axis

`evaluation/axes.py:28,455`

`TOOL_CALL_SPAN = "agent.tool_call"` is hardcoded, and its own comment says targets
using another convention "set it in the scenario's `attack.config`" — but nothing
reads that. `attack.config` is consulted in exactly one place,
`execution/promptfoo.py:56`.

`_unaudited_tool_calls` returns `traced − audited`. When no span matches the
hardcoded name, `traced` is empty, the difference is empty, and
`every_tool_call_audited` reports **pass**. The cross-referencing of two independent
sources — the property that makes the evidence axis worth having — silently stops,
and the axis goes green.

**Fix:** read the span name from `attack.config` (or from the target), and when
`every_tool_call_audited` is asserted while zero spans match the configured name,
return `error` rather than `pass`.

### 02 · high · The report is stamped with a profile it never filtered on

`service/harness.py:676`, `store/sqlite.py:148`

`generate_report` takes a `profile`, passes it to `normalize_batch` as the report's
label, and never passes it to `list_runs` — which has no `profile` parameter at all.
`agentsec report --profile pr` therefore renders a report headed "profile pr" over
whatever runs exist, nightly included.

The reusable CI gate calls exactly this, and `docs/deployment.md` suggests pointing
`AGENTSEC_DB` at a CI cache — the configuration where a mislabelled report stops
being cosmetic.

**Fix:** add `profile` to `ResultStore.list_runs` and filter on it, or drop the
parameter from the report label.

### 03 · high · The report counts every historical run; the coverage resource counts only the latest

`reporting/normalizer.py:127`, `store/sqlite.py:285`

`verdict_counts` deliberately dedupes to the latest run per scenario, with a comment
explaining why: "counting every historical run would let a scenario that failed fifty
times last month dominate today's picture." `normalize_batch` does no such thing.

Reproduced: running the same four scenarios twice, then `agentsec report`, produced
`secure: 4`, `blocking_count: 4`, and a `blocking_scenarios` list naming
`AGT-TENANT-001` and `AGT-MEMPOIS-001` twice each. The HTML dashboard and
`agentsec://coverage` now disagree about one database.

**Fix:** roll up the latest run per (scenario, target) for the headline counts, and
show history as an explicit trend rather than as today's totals.

### 04 · medium · The axis rollup is computed and then never rendered

`reporting/normalizer.py:133`, `reporting/templates/report.html.j2`

`normalize_batch` builds `axis_counts` — pass / fail / not_tested / error for each of
the four axes — and the template renders verdict cards, a table and collapsible
detail, but never touches it. The four-axis contract is the product's central idea and
the one metric the dashboard omits. There is also no filtering, no sorting and no
trend, while the roadmap describes a "metrics dashboard".

`docs/reviews/assets/purple-dashboard.html` in this commit is a worked reference for
the missing view, built from the same JSON. `purple-dashboard.zh-TW.html` is the same
page in Traditional Chinese; both are self-contained single files. Enum values
(`secure`, `detection_gap`, `not_tested`, …), code identifiers and CLI flags stay in
English in the translation, because they are the strings the evaluator actually emits —
translating them would put a name in the report that does not exist in the JSON.

**Fix:** render `axis_counts` as a segmented bar per axis; add verdict/severity
filters and a per-scenario verdict history.

Related, in the existing template's palette: `--warn` (`#b26a00`) and `--fail`
(`#c0392b`) sit ΔE 11.2 apart in normal vision and 5.1 under deuteranopia — hard to
tell apart even with full colour vision. Re-stepping warn toward `#a06d00`/`#c98a00`
clears the normal-vision floor.

### 05 · medium · Extra MCP tool arguments are silently dropped, not refused

`mcp/server.py:151-201`

The README states that tool schemas "reject `url`, `sql`, `command`, `path`, `token`
and friends, with `additionalProperties: false`". Verified against a real stdio
client, they do not:

```
call  agentsec_preview_run {target_id:"demo-agent-fixture",
                            url:"http://attacker.example/x"}
→     {"ok": true, ...}          no error · no audit row

tools/list advertises, for all 11 tools:
      required = []   additionalProperties = <unset>
```

The generated callable in `_make_tool_callable` carries a synthesized signature
containing only declared properties, so FastMCP drops unknown keys before
`validate_arguments` — the one place that holds the real schema — ever sees them.

Not exploitable: the argument has no effect. But the audited-refusal property the
project leans on, and that `.claude/hooks/guard_agentsec.py` exists to reinforce,
does not hold at this boundary.

**What does hold, confirmed:** `required`, `pattern`, `enum`, `maxItems` and
read-only mode were all enforced server-side.

**Fix:** give the generated callable a `**kwargs` tail so unknown keys reach
`validate_arguments` and are refused and audited rather than discarded.

### 06 · medium · Evidence-backend URLs bypass the private-address guard

`policy/allowlist.py:80`, `evidence/wazuh.py:92`

`_check_endpoint` inspects `target.adapter.base_url`, and only when
`adapter.kind == "http"`. `target.evidence.wazuh.url` and the OTel endpoint are never
checked — so a public Wazuh Indexer URL in `policy/targets.yaml` is accepted, and
`WAZUH_INDEXER_USER` / `WAZUH_INDEXER_PASSWORD` are sent to it over
`httpx.BasicAuth`. The README's "endpoints must be private" reads as covering all of
them.

Related: `_is_private_host` treats an unresolvable name as private, with a comment
that "the run itself will fail loudly if it is not" — nothing re-checks at run time,
so a name that does not resolve at config load and resolves publicly at run time is
never caught.

**Fix:** run every configured backend URL through `_check_endpoint`, and re-assert the
check at collection time rather than only at load.

### 07 · medium · `start_run` does not require the prior preview it documents

`mcp/contract.py:167`, `service/harness.py:284`

The tool description says "Requires a prior preview" and the README says
"`agentsec_start_run` requires it". `HarnessService.start_run` records no preview
state and enforces nothing — a first call runs immediately.

**Fix:** either record a short-lived preview marker per (target, profile) and require
it, or reword both the tool description and the README to "always preview first" as
advice.

### 08 · medium · Confirmed for issue #7: read-only mode still advertises all eleven tools

`mcp/server.py:107`

Issue #7 lists "a real stdio MCP client smoke test verifies capability listing" as an
unmet acceptance criterion. Done, and it confirms the report: with
`AGENTSEC_MCP_READ_ONLY=1`, `tools/list` returns all 11 tools including
`agentsec_start_run`, `agentsec_promote_finding` and `agentsec_generate_report`, and
`resources/list` is unfiltered. Dispatch refusal works; capability discovery is
unchanged.

Worth noting for deployment option C: because `agentsec_generate_report` is
`read_only=False`, the read-only "report gateway" is the one process that cannot
generate a report.

**Fix:** track under issue #7 — no separate work item.

### 09 · low · Quarantine expiry silently reinterprets a non-UTC timestamp

`policy/guard.py:102`

`datetime.fromisoformat(quarantined_until).replace(tzinfo=UTC)` overwrites an existing
offset instead of converting it. `2026-08-01T00:00:00+08:00` becomes
`2026-08-01T00:00:00Z`, and the quarantine runs eight hours longer than the author
wrote.

**Fix:** `if until.tzinfo is None: until = until.replace(tzinfo=UTC)`.

### 10 · low · `must_fire` has no lower time bound

`evaluation/matchers.py:118`

`match_alert` rejects an alert only when `ts > deadline`. An alert that fired *before*
`window_start` still satisfies a `must_fire`. Not reachable today — the OpenSearch
collector bounds `gte` at query time and fixtures are rebased into the window — but
the guarantee lives in the collector, not the matcher, so a new collector loses it
silently.

**Fix:** reject `ts < window_start` in `match_alert` too.

### 11 · low · Run-id minting races, and a collision overwrites the earlier run

`service/harness.py:796`, `store/sqlite.py:115`

`_next_run_id` reads `list_runs(limit=1000)`, computes `max + 1` in Python, and
`save_run` is `ON CONFLICT(run_id) DO UPDATE`. Two processes sharing a workspace mint
the same id and the second silently overwrites the first — losing a run without a
trace, in the tool whose job is to be the record. The `limit=1000` scan is also a
ceiling on runs per day.

**Fix:** mint the id inside the insert transaction, or use an `INSERT`-only path so a
collision raises instead of overwriting.

### 12 · low · The guard hook over-matches, and the README's first command is blocked by it

`.claude/hooks/guard_agentsec.py:30,84`, README §2

Production markers are matched as bare substrings anywhere in the command. Hit
organically during this review: `grep -rn "Live Artifact" docs/` was refused because
`"live"` appears in the name of the project's own documented feature.

More importantly, the exemption at line 84 tests the *whole command*, so any command
mentioning `localhost` anywhere exempts every marker in it —
`curl https://prod.customer.com --proxy localhost` passes the check.

Separately: `agentsec run` is denied by both `.claude/settings.json` and the hook,
deliberately and correctly — but README §2 tells a new user to run exactly that, with
no note that inside Claude Code the route is `agentsec_start_run`.

**Fix:** match markers against the parsed host rather than the raw string, scope the
exemption to the same token as the marker, and add one line to README §2.

Also, `.github/workflows/agentsec-gate.yml` interpolates `${{ inputs.* }}` directly
into `run:` blocks; move them to `env:` indirection. `permissions: checks: write` is
granted but never used.

---

## What was fixed

Findings 01–03 are fixed on this branch. The bundled corpus is unaffected: the same
four verdicts, the same exit 1, and `agentsec validate --strict` still clean.

### 01 — the cross-reference has to actually run

`evaluation/axes.py`, `scenario/validator.py`

`tool_call_span_name()` and `tool_name_attribute()` read
`spec.attack.config.tool_call_span` / `.tool_name_attribute`, defaulting to the old
constants. `_unaudited_tool_calls` is replaced by `_every_tool_call_audited_check`,
which returns `error` — never `pass` — when no span carries the configured name, or
when matching spans carry no tool-name attribute. The message names the span names
actually seen and points at the config key.

`agentsec validate` gains `tool_audit_without_spans`: a warning when
`every_tool_call_audited` is asserted (it defaults to `true`) while the contract
collects no OTel evidence, so the author hears about it before committing rather than
from a red nightly.

Demonstrated end to end against a doctored fixture whose spans are named
`agent.invoke_tool`:

| Scenario | Before | After |
|---|---|---|
| Spans named differently, nothing declared | `secure`, evidence **pass** | `error`, evidence **error** |
| Same, with `attack.config.tool_call_span` declared | — | check runs; passes on real evidence |
| Bundled corpus | 2 secure / 2 gaps, exit 1 | unchanged |

### 02 — the report filters on the profile it labels

`store/sqlite.py`, `service/harness.py`, `cli.py`, `mcp/contract.py`

`ResultStore.list_runs` takes `profile`; `generate_report` passes it. `profile` is now
optional everywhere — omit it to report across every profile, and the report says
`"all"` rather than claiming a profile the caller never chose. `--profile` on
`agentsec report` and the `profile` field on `agentsec_generate_report` lost their
`pr` default accordingly.

### 03 — the rollup counts the latest run per scenario

`reporting/normalizer.py`, `service/harness.py`

New `latest_per_scenario()` keeps the most recent summary per (scenario, target),
breaking `created_at` ties on `run_id` — a whole batch shares a timestamp to the
second, so the tiebreak is load-bearing. `generate_report` narrows history through it
before the rollup and before JUnit, and adds `superseded_runs` so the JSON stays honest
that history exists.

The original repro, running the four scenarios twice:

| | Before | After |
|---|---|---|
| `total_runs` | 8 | 4 |
| `secure` | 4 | 2 |
| `blocking_count` | 4 | 2 |
| `blocking_scenarios` | each listed twice | one entry each |
| agrees with `verdict_counts` | no | yes |

### 04 — the axis rollup reaches the page

`reporting/templates/report.html.j2`, `reporting/normalizer.py`, `service/harness.py`

The report now renders `axis_counts` as a segmented bar per axis, each segment labelled
in text and carrying a shape glyph so status never depends on colour alone. Added
alongside it:

* **Filters** — verdict (all / gaps / secure / blocking) and severity, driven by inline
  JS over `data-` attributes, filtering the table and the detail cards together, with an
  empty state when a combination matches nothing. Hidden in print.
* **Trend** — `verdict_history()` returns the per-scenario verdict timeline the rollup
  drops, capped at ten runs each, rendered as a sparkline with the latest run outlined.
  This is the other half of finding 03: the history is not noise, it just must not
  distort today's counts.
* **Palette** — `--warn` moved from `#b26a00` to `#8f6200` (dark `#d9a441`). Against
  `--fail` the old pair sat ~5 ΔE apart under deuteranopia and ~11 in normal vision,
  below the threshold where a full-colour reader can tell them apart.

The page stays a single self-contained file: inline CSS and JS, no external asset of any
kind, and the existing self-containment test still passes.

### 05 — unknown arguments are refused, not dropped

`mcp/server.py`

New `_publish_declared_schema()` does two things to each registered tool: replaces the
advertised `parameters` with the schema declared in `mcp/contract.py`, so a client is
told the truth about `pattern`, `enum`, `required` and `additionalProperties`; and sets
`extra="forbid"` on the derived argument model, so an unknown key is refused at the
protocol boundary rather than discarded. It raises if FastMCP's internals are not the
expected shape — a hardening step that quietly did nothing is the failure this project
is about.

Before / after, same call:

```
agentsec_preview_run {target_id: "demo-agent-fixture", url: "http://attacker.example/x"}
  before →  {"ok": true, ...}       no error, no trace
  after  →  isError: true           extra_forbidden at 'url'

tools/list, all 11 tools
  before →  required: []   additionalProperties: <unset>
  after  →  required: ["target_id"]   additionalProperties: false
```

The refusal happens before the call reaches `HarnessService`, so it lands in the
client's error rather than in `audit_log`. That is the accepted cost of not reaching
into FastMCP's dispatch path: a security control implemented by patching another
library's internals fails silently the first time that library moves. `model_dump_one_level`
only iterates declared fields, so there is no supported way to receive an extra
argument and audit it.

### 06 — every URL the target can dial

`policy/allowlist.py`, `evidence/{wazuh,otel,tool_audit,state_diff}.py`

`_check_endpoint` now walks `adapter.base_url` **and** every evidence backend URL. New
`assert_private_url()` re-asserts the rule at collection time in all four collectors,
closing the gap left by treating unresolvable names as private at load time — a name
that does not resolve when the allowlist loads and resolves publicly when a collector
dials it is now caught. It raises `EvidenceUnavailable`, so a refusal degrades the axis
to `error` rather than aborting the batch.

### 07 — the preview claim, corrected rather than enforced

`mcp/contract.py`, `README.md`, `README.zh-TW.md`

Documentation fix, deliberately. Enforcing a preview only on the gateway would create
exactly the "Claude-only code path" that `service/harness.py`'s own module docstring
forbids, and enforcing it everywhere would break the CLI and CI, neither of which
previews first. The tool description and both READMEs now say preview is a working
convention, and point at what *is* enforced: the approval token, which no tool can mint.

### 08 — read-only mode no longer advertises execution

`mcp/server.py`

`build_server()` skips registering any tool with `read_only=False` when
`AGENTSEC_MCP_READ_ONLY=1`. `tools/list` drops from 11 to 8; `agentsec_start_run`,
`agentsec_promote_finding` and `agentsec_generate_report` are absent rather than
denied, which is what deployment option C describes.

This closes acceptance criterion 1 of issue #7. The rest of that issue — resource
allowlisting, dashboard-safe DTOs and evidence redaction — is a larger design change
and stays open there. Note `agentsec_generate_report` is still `read_only=False`, so a
read-only gateway cannot render a report; that is the right call for a tool that writes
files, and it is the reason #7's DTO work matters.

### 09 — quarantine expiry converts instead of overwriting

`policy/guard.py` — `if until.tzinfo is None: until = until.replace(tzinfo=UTC)`.

### 10 — `must_fire` is bounded at both ends

`evaluation/matchers.py` — an alert that fired before `window_start` is no longer
evidence of the attack. Unreachable through the shipped collectors, which is why it
belongs in the matcher rather than in whichever collector happens to supply the alerts.

### 11 — run ids are claimed atomically

`store/sqlite.py`, `service/harness.py`

New `run_counter` table and `next_run_id()`, one `INSERT … ON CONFLICT … RETURNING`
statement, so two processes sharing a workspace cannot be handed the same id. Schema
version 2; the table is created by the existing `CREATE TABLE IF NOT EXISTS` script, so
existing databases pick it up without migration. Also removes the
`list_runs(limit=1000)` scan, which doubled as an undocumented ceiling on runs per day.

### 12 — the guard hook matches hosts, not prose

`.claude/hooks/guard_agentsec.py`, `README.md`, `README.zh-TW.md`,
`.github/workflows/agentsec-gate.yml`

Production markers are matched against host-shaped tokens extracted from the command,
and the exemption is scoped to the same token and anchored to a whole label. That fixes
both directions at once: `grep "Live Artifact" docs/` and a `noreply@anthropic.com`
commit trailer are allowed again, while `curl https://prod.customer.com --proxy localhost`
and `example.com.evil.net` are refused — the first used to pass because one `localhost`
anywhere exempted the whole line, the second because the exemption was a plain substring.

`tests/test_guard_hook.py` pins all of it. Both READMEs note that the quick start's
`agentsec run` is refused inside Claude Code and why. The reusable gate workflow passes
caller inputs through `env:` instead of splicing them into `run:`, and drops the
`checks: write` permission it never used.

### Tests added

`test_every_tool_call_audited_errors_when_no_span_matches`,
`test_every_tool_call_audited_honours_attack_config_span_name`,
`test_every_tool_call_audited_errors_when_spans_carry_no_tool_name`,
`test_tool_audit_without_spans_warns`,
`test_report_counts_the_latest_run_per_scenario`,
`test_report_filters_by_profile_it_labels`,
`test_html_report_renders_the_axis_rollup_and_trend`,
`test_run_ids_are_claimed_atomically`,
`test_evidence_backend_url_is_checked_too`,
`test_private_url_is_reasserted_at_collection_time`,
`test_quarantine_with_an_explicit_offset_is_converted_not_overwritten`,
`test_alert_that_fired_before_the_attack_is_not_evidence_of_it`,
plus `tests/test_guard_hook.py` (20 cases) and `tests/test_mcp_gateway.py` (3 cases,
skipped unless the `mcp` extra is present — CI runs them in the gateway job).

182 tests pass; ruff and mypy clean; coverage 76.4%.
