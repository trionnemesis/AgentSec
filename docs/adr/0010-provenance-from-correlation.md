# ADR 0010 — Promote evidence to live from correlation and event time

Status: **Accepted** (2026-09-05)

Decision scope: [#77](https://github.com/trionnemesis/AgentSec/issues/77).
Baseline: `51df65934bb8a3fa2eb7956d616271cef21594c5` (`v0.4.3`).

## Problem and first principles

Provenance answers what a result was observed against. The filesystem is a
transport, not a statement that an event was prerecorded. Conversely, querying
HTTP does not prove that returned data belongs to this run. The existing
kind-only rule underclaims live-written files and can overclaim unverified
network responses. A fixture-derived `secure` must never read as live proof.

We accept option B, with an explicit event-time qualification. This decision
authorizes a separate, regression-first implementation commit before Route A.
It does not declare Route A complete or authorize changing verdict semantics.

## Decision

Retain the published `recorded`, `live`, and `mixed` values and `backends`
diagnostics. Derive source origins from the persisted evidence bundle, not the
transport kind or a target configuration edited after execution.

A telemetry source (`otel`, `wazuh`, or `tool_audit`) contributes **live** only
when all of the following hold:

1. The bundle belongs to this run, and its source has no collector error.
2. `SourceMeta.correlation == "verified"` and the source contains records.
3. Every normalized record has the exact current `run_id`.
4. Every event timestamp (span `start_time`, alert/audit `timestamp`) is timezone
   aware and lies in the inclusive persisted evidence window, no later than
   `collected_at`. The window and collection time must also be timezone aware.

`verified` alone is insufficient: current collectors validate identity but allow
missing OTel/audit timestamps and mark empty collections verified. An empty
file proves no observation. Reporting never rebases or repairs a timestamp.
These checks qualify presentation only: collection behavior, event-time SLA
evaluation, and the stored verdict remain unchanged. A late event inside the
collection window can be live while still failing a shorter detection/response
SLA. A timestamp is not cryptographic authenticity; the reviewed evidence
producer remains a trust boundary.

`trusted_fixture`, absent correlation, unknown source types, missing timestamps,
or insufficient time/correlation evidence conservatively contribute **recorded**.
`state_diff` currently has no correlation attestation, so it is not promoted by
its transport. In this three-value vocabulary recorded is also the conservative
fallback for insufficient provenance; it is not a claim to know when such data
was originally captured. An errored source contributes nothing.

The execution transcript remains a separate origin component. Only a nonempty
persisted transcript from an execution with `ok=True` can contribute. Its stored
`meta.backend == "fixture"` contributes recorded; `http` contributes live.
Unknown/`cli` origin is conservative. Target configuration remains a display
fallback only and cannot promote a historical transcript. A dry-run, refused,
pending, or absent execution cannot become live through an HTTP target setting.

**Mixed** means the run contains both live and recorded components (including
its transcript). A fixture transcript plus verified live telemetry is mixed,
never live. Trust is source-wide: `trusted_fixture` applies to the whole source;
there is no new per-record trust mode. Missing/foreign/conflicting canonical
IDs on live collection continue to fail closed. Inconsistent persisted records
are never promoted by a metadata flag alone.

No components defaults to recorded, the conservative existing enum member.
`live` does not imply a passing verdict, complete detection coverage, or a tested
response. In particular, detection without a contract remains `not_tested`.

## Stored runs and compatibility

Provenance is currently derived when reports/dashboard summaries are generated;
it is not frozen in `Run`. Re-generating a report applies this decision to the
stored source metadata, IDs and timestamps. Existing exported JSON/HTML/JUnit
bytes do not change, and no stored verdict/evidence is rewritten. An old run
with qualified live-written files may move from mixed to live. Older runs
without sufficient provenance can become recorded/mixed. CHANGELOG must call
out this behavior; no migration or schema/enum/version bump is needed.

## Alternatives rejected

- Keep kind-only inference: preserves a demonstrably incorrect transport proxy.
- Mark every file live: relabels prerecorded fixtures as real-system proof.
- Promote solely on `verified`: empty and untimed files can satisfy the flag.
- Add a fourth value: changes the published contract without establishing truth.
- Change collectors/evaluator to enforce a new timestamp contract: unnecessary
  for a presentation correction; would alter the separate truth/SLA boundary.

## Implementation and acceptance boundary

First reproduce a current-run, live-written file being labeled recorded/mixed.
Then change only normalizer inputs, reporting derivation, service passthrough,
tests and matching documentation. Pin verified file, fixture, mixed,
empty/unverified, timestamp boundaries, foreign IDs, errors, historical target
edits, no-execution cases and the unchanged bundled verdict matrix.

Four axes, precedence, `not_tested != pass`, collectors' fail-closed behavior,
published schema shapes, the MCP surface and `evaluation/` are unchanged. The
legacy `fixture_derived` field retains its all-recorded rule; its description
and banners acknowledge conservative fallback. Route A
must separately prove one genuine Claude Code/AgentShield gap, one minimal fix,
the same-scenario live rerun and a reviewed replay regression. Unit-test
evidence does not satisfy that live acceptance.
