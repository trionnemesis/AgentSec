# ADR 0009 — The repository scan is the entry point, and a risk is not a verdict

**Status:** Accepted · **Date:** 2026-08-06

Converges [#32](https://github.com/trionnemesis/AgentSec/issues/32). Two
decisions, taken together because neither survives on its own: where the product
starts, and what the new plane is allowed to say.

## Context

#32 diagnosed the repository accurately: the deterministic core is focused, and
the product surface around it has diverged. Five planes, three interfaces, and no
stated order between them. Its proposed remedy was to converge on a developer
golden path built from façade commands over the CI gate — `agentsec check`,
`agentsec verify`.

Trying to write that façade surfaced the problem underneath.

`agentsec check --target order-agent-staging` needs `order-agent-staging` to
exist. A target is an allowlist entry, a reachable staging agent, and — for the
detection axis to say anything — a Wazuh or OTel backend. That is a security or
platform team's work. The engineer #32 identifies as the primary user cannot
reach the first command of the golden path without it.

Worse, the ordering is backwards on its own terms. Configuring a target is a
real cost, and nothing in the product told anyone *why it was worth paying* for
their particular repository. The scenario catalogue is generic; the question an
engineer actually has is "is any of this about my code?"

Meanwhile `project/discovery.py` had been shipped and consumed by nothing. It
produced a careful, traversal-safe inventory of skills, agents, hooks, settings,
instructions and MCP servers — and the only thing reading it was a counts block
in the dashboard header. The material for the missing first step already existed
and was inert.

Two surfaces were also missing outright. **Tool grants**: a repository can hold
no skills, no agents and no hooks, and still hand a model unattended shell access
in four words of `settings.json`. **Memory / RAG**: retrieved context reaches the
model with the authority of a reviewed instruction and no reviewer diffs it.

## Decision

### 1. `agentsec scan` is the entry point

The golden path starts at a repository, not a target:

```
agentsec init → agentsec scan → agentsec scan --verify -t <id> → dashboard
```

`scan` requires nothing but a checkout. It reads the discovered surfaces,
applies the deterministic rules in `inspect/`, and ranks what it finds. The CI
gate remains the destination — it is now the second step, reached once the scan
has said which scenarios are worth the target configuration.

Discovery grows the two missing surfaces. `tool_grants` is derived from
`settings.json` permissions, one entry per rule rather than a count, because
"is this configured" is not the question — *which* tool under *which* constraint
is. `memory` is a declared manifest location, defaulting to `.claude/memory`.

### 2. A risk is a reason to test, never a result

The new plane gets its own vocabulary and is never merged into `purple`:

* `severity` — how bad **if real**. A property of the rule, fixed, never
  inferred from the repository.
* `verification` — `verified` (a covering scenario produced a verdict) /
  `verifiable` (one exists, has not run) / `not_verifiable` (nothing in the
  catalogue exercises this surface).

`not_verifiable` is the default and the common case. It is deliberately neither
a pass nor a failure: it reports that AgentSec found something and cannot settle
it.

`agentsec scan` exits `0` even with critical risks outstanding. Only a run
produces `1`. A gate that blocks on a static match teaches its team to bypass
the gate.

### 3. The bridge reuses `config-surface:`, and rules never carry content

Correlation reuses the tag convention [#25](https://github.com/trionnemesis/AgentSec/issues/25)
introduced, extracted into `scenario/surface_tags.py` and shared with
`posture/coverage.py`. Two planes answering the same question differently would
make the dashboard contradict itself.

Rules report counts, line numbers, Unicode codepoint names and their own marker
vocabulary — never the matched text. `project/discovery.py` earns the right to
be published without a second redaction pass by not reading values; a risk plane
that quoted the offending line would spend that property on the way out.

### 4. No model in the risk path either

[ADR 0002](0002-deterministic-verdict.md) refuses an LLM judge for verdicts. The
argument does not weaken one level upstream: a risk plane whose output changed
between two runs of the same commit could not be diffed, gated on, or argued
with.

## Alternatives rejected

**Façade commands over the CI gate (`agentsec check`), as #32 proposed.**
Rejected as the *first* step, not as an idea. It cannot run without a
configured target, so it cannot be an entry point. Everything it proposes about
simplified output and expert-mode demotion is adopted here, one step later.

**Extend `static_posture` instead of adding a plane.** That plane's contract is
"ingest a report someone else's scanner produced". It has no scanner, by design
([#25](https://github.com/trionnemesis/AgentSec/issues/25)). Giving it a
first-party rule engine would mean one plane with two failure modes and two
provenances behind one status field.

**Express risks as `PurpleVerdict`s.** Rejected for the reason ADR 0002 exists.
A static match has executed nothing and given no detection control the chance to
fire; `secure` from a rule that read a file would be a lie in the type system.

**Let rules quote the matched line.** Better UX, and it would move the entire
publication burden onto `publish.py` for the one plane whose input is arbitrary
repository content. Line numbers plus the rule's own vocabulary is enough to
find it in an editor.

**Fire one memory risk per file.** The risk is the retrieval inlet, not the
document. A hundred entries is the same inlet as one, and per-file rows would
bury every other plane.

## Consequences accepted

**A static rule is not proof, and some readers will treat it as one.** Mitigated
in the vocabulary rather than the docs: the CLI prints "no risks matched. That is
not a clean bill of health", `scan` never exits `1`, and `not_verifiable` never
renders green.

**False positives are now possible in a way they were not before.** Discovery
could not be wrong; rules can. The first run against this repository proved it —
`ASI-HOOK-NETWORK-EGRESS` fired on a comment explaining what a proxied `curl`
would do. Fixed by stripping comments before matching hook rules, and pinned by
`tests/test_inspect.py`. The rule that follows: a rule which reports the
*documentation* of a risk as the risk teaches its reader to skip the plane.

**Most risks report `not_verifiable` today.** Only four scenarios carry
`config-surface:` tags, and none covers tool grants or settings. That is a
catalogue gap, now visible per-risk instead of invisible. Listed in
[`docs/feature-matrix.md`](../feature-matrix.md).

**`AGT-CONFIG-003` was retagged** from `.claude/hooks/guard_agentsec.py` to
`.claude/hooks`. Nothing in that scenario is specific to one hook — it seeds an
untrusted filename and asserts on `run_shell_hook` — and the narrow tag meant it
correlated with AgentSec's own repository and with nothing in anyone else's.

**`PUBLISH_SCHEMA_VERSION` goes to 1.3.0.** `repo_risk` is required on the
composed dashboard. Minor rather than major: a consumer reading the planes it
knows is untouched.
