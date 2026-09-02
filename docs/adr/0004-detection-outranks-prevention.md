# ADR 0004 — `detection_gap` outranks `prevention_gap`

**Status:** Accepted · **Date:** 2026-07-28

## Context

Four axes produce sixteen-plus combinations, but one verdict has to be reported.
The ordering decides which finding a team fixes on Monday morning.

The intuitive ordering puts prevention first: the attack succeeded, that is the
emergency. Consider the two cases side by side, though:

| | Prevention | Detection | Situation |
|---|---|---|---|
| A | fail | pass | The attack worked. An alert fired. You know, you can measure it, you can fix it. |
| B | fail | fail | The attack worked. Nothing fired. You do not know it is happening, and you will not know next time either. |

Both are prevention failures. Only B is unbounded. In A you can quantify exposure
from your own alerts, tell customers what happened, and confirm the fix landed. In
B you have none of that — including no way to know whether B has been happening in
production for a year.

## Decision

```
error  >  detection_gap  >  prevention_gap  >  evidence_gap  >  response_gap  >  secure
```

`detection_gap` is returned whenever the detection axis fails, regardless of
prevention. The rationale surfaced to the user distinguishes the two sub-cases:

- prevention passed, detection failed → *"the attack was blocked but nothing
  alerted on the attempt"*
- prevention failed, detection failed → *"the attack succeeded and nothing
  alerted"*

Note that the first sub-case is still a real finding. A control that blocks
silently gives you no signal that anyone is trying, so you cannot tell a
successful defence from an absence of attacks — and you will not notice when a
refactor removes the control.

`error` outranks everything for the same reason applied to the harness itself. A
run whose evidence pipeline broke has no opinion about your security and must not
be allowed to imply one.

## Alternatives rejected

**Prevention first.** Rejected on the argument above: it directs attention to the
recoverable case and lets the unbounded one sit behind it in the queue.

**A numeric score across the axes.** Rejected: a score is comparable but not
actionable. "AGT-TENANT-001 scored 0.4" does not tell anyone what to do; "the
tenant boundary is broken and instrumented" does.

**Report all four axes and no overall verdict.** Genuinely tempting, since the
axes carry the real information — and they are all preserved in the run record and
the report. Rejected as the *primary* output because CI needs one value to gate
on, and a dashboard needs one column to sort by. Refusing to summarise pushes that
decision into every consumer, where it gets made inconsistently.

## Consequences

**Accepted cost.** The verdict alone under-describes a run: `detection_gap` does
not say whether prevention also failed. Mitigated by always carrying the four axis
statuses alongside it, in the CLI output, the JUnit detail, the HTML report and
the JSON.

**Accepted cost.** Teams whose detection coverage lags their prevention coverage
will see a wall of `detection_gap` on first adoption. That is an accurate
description of the situation rather than a flaw in the ordering, and the `pr`
profile lets them start with `gate: warning` while they catch up.

**Gained.** The verdict names the first priority, while the preserved axes name
the complete work. `detection_gap` with prevention `pass` means fix detection
only; with prevention `fail`, fix both the application or policy control and
detection. `prevention_gap` means fix the control. A team can route the work
without inventing meaning that the verdict alone does not carry.
