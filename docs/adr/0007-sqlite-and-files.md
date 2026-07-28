# ADR 0007 — SQLite plus JSON files, not a service database

**Status:** Accepted · **Date:** 2026-07-28

## Context

Runs, findings and audit records need to persist. The reflex for anything with a
dashboard in its future is Postgres.

For this workload that reflex is wrong in a specific way. The dominant
requirements are *reproducibility* and *portability*: a verdict from six months
ago must be re-readable, and reproducing a finding on a colleague's machine should
not require provisioning anything.

## Decision

**SQLite** for structured records (runs, findings, audit log), **JSON files** for
evidence bundles and reports.

```
results/
  agentsec.db          runs · findings · audit_log
  evidence/RUN-*.json  normalised bundles
  raw/RUN-*.json       untouched executor output (promptfoo, etc.)
  reports/*.html|json|xml
```

Why this split:

**A single file attaches to a ticket.** "Reproduce this finding" becomes "here is
the .db and the evidence directory" — no credentials, no VPN, no schema migration.

**Evidence belongs in files, not blobs.** Bundles are large, append-only, and
frequently inspected ad hoc. `jq` over a JSON file beats a `TEXT` column, and
`git diff` on two bundles is genuinely readable.

**Raw executor output is kept but not parsed into the database.** When a promptfoo
result looks wrong, you want the original bytes.

The one non-obvious query is worth calling out. `verdict_counts()` uses
`ROW_NUMBER() OVER (PARTITION BY scenario_id, target_id ORDER BY created_at DESC)`
and counts only the latest run per scenario — otherwise a scenario that failed
fifty times last month dominates today's picture, and the dashboard measures CI
frequency rather than posture.

## Alternatives rejected

**Postgres from the start.** Rejected: adds a service to run, back up and migrate
before there is a second writer. Nothing in the current design needs concurrent
writes from multiple hosts.

**Everything in JSON files, no database.** Rejected: `find_open_finding` and the
latest-run-per-scenario aggregate are real queries. Hand-rolling them over a
directory scan is slower to write and slower to run than one indexed table.

**Everything in SQLite, evidence as blobs.** Rejected: loses ad-hoc inspection,
and makes the database grow without bound in a way that hurts the portability
argument.

## Consequences

**Accepted cost.** No concurrent multi-host writes. WAL mode handles concurrent
readers and a single writer, which covers the CLI, one MCP process and CI runs on
separate workspaces. A team deployment needs a real database, and the
`ResultStore` interface is where that swap happens.

**Accepted cost.** `evidence_ref` is a path, so moving a workspace can orphan
bundles. Paths are stored workspace-relative to keep this survivable.

**Accepted cost.** `schema_version` exists but there is no migration runner. At
version 1 that is honest; write one before shipping version 2 rather than
pretending the column is doing work.

**Gained.** Zero setup. `pip install -e .` then `agentsec run` works, which is
what makes the offline demo — and therefore the whole first-contact experience —
possible.
