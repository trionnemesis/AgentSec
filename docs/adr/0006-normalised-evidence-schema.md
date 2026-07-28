# ADR 0006 — Normalise evidence; don't query vendors from the evaluator

**Status:** Accepted · **Date:** 2026-07-28

## Context

The evaluator needs Wazuh alerts, OTel spans, tool-audit records and database
diffs. The direct approach is to query each system where it is needed: the
detection axis calls OpenSearch, the evidence axis calls Tempo.

That makes the evaluator's correctness depend on four vendor APIs, and it makes
every axis untestable without those systems running. It also quietly makes Wazuh
load-bearing: swapping SIEMs would mean editing the code that decides pass/fail,
which is the last code you want to touch for an infrastructure migration.

## Decision

Collectors translate each vendor's format into `schemas/evidence.schema.json`. The
evaluator only ever sees that shape.

```
Wazuh / OpenSearch ─┐
OTLP / Tempo       ─┤
tool audit JSONL   ─┼─→ Evidence bundle ─→ Evaluator ─→ Verdict
DB snapshot diff   ─┘     (normalised)      (pure fn)
```

Three properties fall out, and each is load-bearing:

**Swapping a SIEM is one file.** Splunk instead of Wazuh means writing
`evidence/splunk.py` and adding a backend to `target.schema.json`. The evaluator,
the scenarios and the reports do not change.

**A collector failure degrades its axis to `error`, never to `pass`.** This is the
single most dangerous bug available to a purple harness: the evidence pipeline
breaks, every assertion finds nothing, every `must_not` passes, and the dashboard
turns green at exactly the moment it should be screaming.
`tests/test_pipeline.py::test_missing_evidence_file_degrades_to_error_not_pass`
deletes a fixture and asserts the verdict becomes `error`.

**Fixture timelines are rebased into the run window.** Recorded evidence carries
the wall-clock time it was captured; `within_seconds` compares against the current
run. Without rebasing, every fixture would become a false `detection_gap` as soon
as the clock moved past its timestamps. Relative offsets are preserved, so an
alert recorded three seconds after the first event still tests `within_seconds: 3`
honestly. Only file-backed collection rebases — live backends already query the
real window.

Two deliberate omissions from the bundle:

- **Tool arguments are stored as a digest, not plaintext.** Arguments are the most
  likely place for secrets and customer data, and the bundle is designed to be
  shareable with a read-only gateway.
- **The state-diff collector never issues SQL.** It reads target-declared logical
  collections, and raises if the target reports one the operator did not declare —
  a snapshot scope wider than what was signed off is a misconfiguration, not
  something to quietly accept.

## Alternatives rejected

**Query vendors directly from the evaluator.** Rejected: couples pass/fail to four
APIs and makes the axes untestable offline.

**OpenTelemetry as the single evidence bus, with Wazuh exporting into it.**
Architecturally cleaner, and worth revisiting. Rejected now because it requires
every telemetry source to be OTel-native — most SIEM deployments are not — and it
would make OTel a hard dependency of the deterministic core.

**Store raw vendor responses and normalise at evaluation time.** Rejected: the
run record would then only be interpretable by the exact code version that wrote
it. Normalising at collection time makes a bundle from a year ago still readable,
which matters when reproducing an old finding.

## Consequences

**Accepted cost.** Normalisation loses vendor-specific fields. Mitigated by
`fields` on alerts (the flattened source document) and `attributes` on spans, so a
contract can assert on anything the source carried.

**Accepted cost.** A collector is a real piece of work — roughly a hundred lines
plus tests — so integrating a new telemetry source is not free. That is the right
place for the cost, since it is paid once per organisation rather than once per
scenario.

**Gained.** The evaluator is a pure function over typed data, testable with
hand-built bundles and no infrastructure. Most of `tests/test_evaluator.py` runs
in milliseconds.
