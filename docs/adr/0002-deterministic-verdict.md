# ADR 0002 — No LLM in the pass/fail decision

**Status:** Accepted · **Date:** 2026-07-28

## Context

The tempting design is an LLM judge: feed it the transcript, the alerts and the
scenario, ask "did the agent behave safely?". It handles nuance, needs no
assertion language, and adapts to scenarios nobody anticipated.

It also cannot be a merge gate. A judge that returns a different answer on
Tuesday than on Monday, for the same code, teaches engineers that the gate is
noise. Once that belief forms, the gate is dead regardless of its accuracy.

There is a subtler problem. An LLM judge evaluating an LLM agent shares the
agent's blind spots. A prompt injection convincing enough to fool the agent has a
good chance of reading as benign to the judge — and a purple-team tool that fails
in correlation with the system it tests is worse than none, because it produces
confident green results precisely when it is wrong.

## Decision

The verdict is a pure function of `(contract, evidence)`.

```python
def resolve_verdict(prevention, detection, evidence, response) -> PurpleVerdict
```

No clock, no I/O, no model. Assertions are declarative and matched by explicit
comparators. `tests/test_evaluator.py::test_evaluator_is_deterministic` asserts
the property directly.

Where language models *are* used:

| Task | Model? | Why |
|---|---|---|
| authoring a contract | yes | judgement about threats, reviewed by a human |
| locating the responsible code | yes | reading comprehension over a repository |
| writing the fix and the regression | yes | reviewed like any other change |
| **deciding pass/fail** | **no** | must be reproducible for CI to depend on it |
| explaining a failure to a human | no | `_rationale()` is templated from the failed checks |

## Alternatives rejected

**LLM judge for the verdict.** Rejected on reproducibility and correlated
blindness, above.

**LLM judge as a fifth advisory axis.** Genuinely appealing: it might catch
something the contract missed. Rejected for the first release on a narrower
ground — an advisory signal that cannot fail the build will be ignored, and one
that can is the reproducibility problem again. Worth revisiting once the
deterministic axes are trusted, and only as a *finding generator* that proposes
new scenarios, never as a judge of existing ones.

**Semantic similarity instead of substring matching.** Rejected: an embedding
threshold is a hidden hyperparameter that silently changes verdicts when the model
is updated. Substring and regex matching are crude, and their crudeness is
legible.

## Consequences

**Accepted cost.** Contracts must be written by hand, and a contract can only
catch what its author anticipated. Real bugs will slip past. The mitigation is
that scenarios are cheap and accumulate: every incident becomes a permanent
scenario.

**Accepted cost.** Assertion matching is deliberately literal, which makes it
brittle against reworded agent output. `in_step` scoping and
`policy_decision`-style assertions against structured audit data — rather than
prose — are how a contract stays robust.

**Gained.** `agentsec run` exits 1 for a reason a developer can read, reproduce
locally, and disagree with. That is the whole basis for a gate anyone respects.
