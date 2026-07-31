# Local deployment review — 2026-07-31

Reviewed at `ce4f986` on `main`. Python 3.11.15, clean virtualenv, no network to any
agent or SIEM. The MCP gateway was exercised with a real stdio client (`mcp` 1.29.0),
not a mock.

Interactive dashboard rendering this review:
<https://claude.ai/code/artifact/1bd63b3a-6a33-4303-9e8b-39a895ede90f>

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
the missing view, built from the same JSON.

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

## Suggested order of work

1. **01** — it is the only finding where a control silently reports green.
2. **02** and **03** — both make the dashboard misreport; **03** additionally puts two
   parts of the same codebase in disagreement.
3. **04** — the metrics view the project describes but does not yet render.
4. **05**–**08** — claim-versus-behaviour gaps; each is a small change plus a test.
5. **09**–**12** — correctness and ergonomics.
