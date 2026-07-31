# ADR 0008 — Skill Assurance is a separate bounded context

**Status:** Accepted · **Date:** 2026-07-31

This ADR pins a direction before any code exists. Nothing described under
"Decision" is built yet; the point is to fix the boundaries now, while changing
them is free.

## Context

This repository ships an agent skill of its own,
`.claude/skills/agentsec/SKILL.md`, and it is written as a list of executable
invariants: preview before run, never claim a verdict, never mint approvals,
`not_tested` is not `pass`, a detection gap is two fixes, check the plumbing
before believing the gap. Nothing verifies any of them. `.claude/README.md`
already ranks that file as the one layer a prompt can talk out of — so the
invariants most worth trusting are the ones with the least enforcement behind
them.

Verifying them needs an isolated workspace, a fixture corpus, normalised traces,
a policy guard, a deterministic grader, a CI gate and a report. This repository
has all seven. The reflex is therefore to express a skill evaluation as a
`Scenario` and let the existing evaluator judge it.

That reflex is wrong, and the reason is visible in the type definitions. The
purple-team domain is bound to its semantics at every layer:

| Binding | Where |
|---|---|
| `kind: Literal["Scenario"]`, id `^AGT-[A-Z0-9]+-\d{3}$` | `models/scenario.py:52`, `:317` |
| `Contract` is exactly prevention · detection · evidence · response | `models/scenario.py:293` |
| `Verdict` carries those four axes as required fields | `models/run.py:89` |
| `runs` table has a column per axis | `store/sqlite.py:38` |
| `ExecutionContext.scenario: Scenario` | `execution/base.py:24` |
| `ExecutorName` is a closed `Literal` of four names | `models/scenario.py:35` |

Reusing that vocabulary means answering questions it was never asked. "The skill
did not improve the output" is not a `prevention_gap`. "The skill fired when it
should not have" is not a `detection_gap`. Both would have to be recorded as one
anyway, because the enum has no other slot — and a verdict that sometimes means
"a control failed" and sometimes means "a skill underperformed" is worth less
than either meaning alone. [ADR 0004](0004-detection-outranks-prevention.md)
spends its whole argument on making `detection_gap` mean one specific thing;
diluting it here would undo that.

There is a second reason, less about types. The roadmap's stated bet is that
knowing whether the blue side would have noticed is the durable value. Skill
quality in general — does this skill make the model better at its job — is
orthogonal to that bet. Some of the machinery is shared, but the question is
not, and a repository that answers both is two products sharing a CI file.

## Decision

Skill Assurance lives in this repository as a bounded context named
`skill_eval`, with its own schema, runner protocol, verdict type, store, CLI
namespace and CI workflow. It shares the infrastructure and shares no domain
types.

**Scope is security and operational reliability.** Does the skill trigger when
it should and stay quiet when it should not; does it hold its own process
constraints; does it keep the agent inside the policy boundary; does it stay
stable across harness and model changes. Explicitly out of scope: brand voice,
general-purpose productivity skills, and capability benchmarking as a product.
That line is the precondition for this ADR — see Consequences.

**Two planes over one trace.** A single execution produces one trace, which two
independent evaluators may read. Their verdicts are never merged.

```
                trace + artifacts
                 /             \
   Skill Quality Plane      Purple Security Plane
   SkillEvalVerdict         PurpleVerdict  (unchanged)
```

| Observation | Skill plane | Purple plane |
|---|---|---|
| skill produced the wrong answer | `outcome_fail` | — |
| skill fired on an unrelated task | `false_activation` | — |
| skill skipped `preview_run` before `start_run` | `process_violation` | — |
| poisoned reference talked the agent past an approval | `security_violation` | a normal `AGT-*` scenario |
| leak occurred and nothing alerted | `outcome_fail` | `detection_gap` |

The crossover rule is one sentence: **if the failure is a security behaviour of
the agent, it is an `AGT-*` scenario judged by the existing evaluator, which does
not change.** The skill plane records that a skill caused it; it does not judge
it.

**A separate schema, not an extension.** `kind: SkillEvalSuite`,
`apiVersion: agentsec.dev/v1alpha1` — deliberately not `v1`, because this
surface will move and the purple schema must not be dragged along with it.

**A separate runner protocol.** `SkillHarnessRunner`, parallel to `RedExecutor`.
Widening `ExecutorName` is not the cheaper option it looks like: it is a closed
`Literal` reflected in `schemas/scenario.schema.json`, the semantic validator and
all four bundled scenarios. A second protocol touches none of them.

**A separate database file.** `results/skill_eval.db`, not new tables in
`agentsec.db`. `_init_schema` writes the version row only when it is absent
(`store/sqlite.py:100`), so adding tables to the existing file would work — right
up until `SCHEMA_VERSION` moves to 2, at which point every existing database
silently keeps claiming version 1. [ADR 0007](0007-sqlite-and-files.md) accepted
"no migration runner" as honest at version 1; a second domain in the same file
would quietly spend that honesty. A separate file keeps version 1 true.

**Ablation attributes controls, not capability.** Variants exist to answer
"which layer actually held the line" — skill, `settings.json` permission, or
`hooks/guard_agentsec.py` — because a suite that passes only because the hook
blocked everything reports a skill that does nothing as a skill that works.
Trigger-gap and content-lift comparisons are read as attribution of safety
behaviour, not as a capability score.

**No new MCP tools in the first phase.** If they are added later, they take a
committed `suite_id` and a profile name, and nothing else.
[ADR 0003](0003-constrained-mcp-tools.md) applies unchanged: prompts, skill
paths, workspace paths and runner commands are resolved from reviewed files, not
passed by the caller. `run_arbitrary_prompt` and `eval` are already in
`FORBIDDEN_TOOL_NAMES` and the build fails if they reappear.

**A separate workflow, not a new job in `ci.yml`.** Gate layering:

| Profile | Contents | Blocking |
|---|---|---|
| `static` | frontmatter, reference paths, scripts, schema, digests | yes |
| `pr` | one harness, core cases, deterministic graders only | yes |
| `nightly` | repetitions, ablation, negative and adversarial cases | trend only |
| `release` | cross-harness, full corpus, skill version comparison | yes |
| semantic judge | rubric cases | advisory, never gating |

[ADR 0002](0002-deterministic-verdict.md) holds without amendment: no model
decides pass/fail. Graders are exit codes, schema validation, file contents,
static analysis, tool-call traces and refusal evidence.

**Stochastic results are recorded as rates, not verdicts.** A trial count, a pass
rate and an interval — never a single-trial pass/fail promoted to a gate.

**Comparisons must name what moved.** Alongside the existing `contract_changed`
notion: `skill_changed`, `suite_changed`, `fixture_changed`, `model_changed`,
`harness_changed`. A score that fell after a model upgrade is environment drift,
and reporting it as a skill regression is the same error
`.claude/skills/agentsec/SKILL.md` already warns about for run comparison.

## Alternatives rejected

**Skill evaluation as an ordinary `Scenario`.** The cheapest option by line
count, and it was rejected on semantics: `AGT-*` ids, the four-axis contract, the
`PurpleVerdict` enum and the `runs` columns would each have to be loosened, and
what they mean would be loosened with them. The cost lands on every future reader
of a verdict, not on the author of the change.

**A separate repository.** Correct eventually, wrong now. The reusable parts —
policy guard, allowlist, fixtures, report normaliser, store, CLI, CI — are real
and would have to be duplicated or extracted into a third package before anything
ran. Revisit when the scope crosses the security line stated above; at that point
the shared infrastructure is no longer the dominant term and the split is cheap.

**Promptfoo's own assertions as the pass/fail source.** Rejected for the same
reason the existing promptfoo executor parses transcripts back into this
evaluator rather than reading promptfoo's verdicts: pass/fail is the product. An
external runner deciding it moves the definition of "secure" outside code review.

**New tables in `agentsec.db`.** Rejected on the `schema_version` argument above.

**An `agentsec_eval(prompt=...)` or `agentsec_run_skill(path=...)` MCP tool.**
Rejected outright, and the existing contract tests already reject it for us. A
gateway that reads adversarial content by design does not gain a tool that
executes caller-supplied prompts against a caller-supplied path.

## Consequences

**Accepted cost.** Two vocabularies in one repository, and contributors must know
which plane a failure belongs to. The crossover rule is deliberately one
sentence, and the mistake it prevents — a security finding recorded only as a
skill-quality note, invisible to the gate — is the one worth spending a rule on.

**Accepted cost.** Duplicated plumbing: a second loader, validator, store and
reporter, each thinner than its purple counterpart but none of them free. This is
the price of not widening the types, and it is paid once.

**Accepted cost, and the significant one.** CI gains a dependency on model
credentials for the first time. All three current jobs run without them, which is
why the deterministic core is trustworthy in a way the 🟡 integrations are not. A
flake policy — repetitions, pass-rate threshold, quarantine path — must exist
before the first stochastic job merges. A nightly job that goes red on variance
gets muted within a month, and a muted gate is worse than an absent one because
it looks like coverage.

**Accepted cost.** Sequencing. The roadmap's first near-term item — one real
staging agent, end to end — is unfinished, and Skill Assurance ships after it.
Two half-proven subsystems is a worse position than one proven one, and the
staging run is what earns the CI gate the whole product rests on. The `static`
profile is the exception: it needs no model, no harness and no credentials, so it
can land early and start paying immediately.

**Accepted cost.** The scope line will be under pressure. Every skill anyone
writes will look like a candidate, and the reasons to say yes will be individually
reasonable. When it is no longer honestly holding, the answer is the separate
repository — not a quiet widening of what this context claims to cover.

**Gained.** The skill's non-negotiables become executable. "Never mint approvals"
stops being a sentence a sufficiently persuasive document can argue with, and
becomes a case that fails the build.

**Gained.** Attribution. Without ablation, a clean result cannot distinguish a
skill that guided the agent correctly from a hook that blocked the agent's
mistake — and those two states call for opposite next actions.

**Gained.** `PurpleVerdict` still means exactly what
[ADR 0002](0002-deterministic-verdict.md) and
[ADR 0004](0004-detection-outranks-prevention.md) say it means. That was the
thing most at risk, and it is the thing the boundary protects.
