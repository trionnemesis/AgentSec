"""SQLite result store.

SQLite is not a placeholder for "a real database later" — for a harness whose
results must be reproducible, portable and diffable, a single file you can
attach to a ticket is the right shape. Swap it when you need concurrent writers
from several hosts, not before.

Evidence bundles live on disk as JSON and are referenced by path: they are large,
mostly append-only, and you want to be able to `jq` them.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentsec.errors import FindingNotFound, RunNotFound
from agentsec.models.finding import Finding, FindingStatus
from agentsec.models.run import Run

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS runs (
    run_id          TEXT PRIMARY KEY,
    scenario_id     TEXT NOT NULL,
    target_id       TEXT NOT NULL,
    profile         TEXT NOT NULL,
    status          TEXT NOT NULL,
    purple_verdict  TEXT,
    prevention      TEXT,
    detection       TEXT,
    evidence        TEXT,
    response        TEXT,
    created_at      TEXT NOT NULL,
    finished_at     TEXT,
    scenario_digest TEXT,
    payload         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_scenario ON runs (scenario_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_target   ON runs (target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_verdict  ON runs (purple_verdict);

CREATE TABLE IF NOT EXISTS findings (
    finding_id      TEXT PRIMARY KEY,
    scenario_id     TEXT NOT NULL,
    target_id       TEXT NOT NULL,
    status          TEXT NOT NULL,
    severity        TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    first_seen_run  TEXT NOT NULL,
    last_seen_run   TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    payload         TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_key
    ON findings (scenario_id, target_id, status)
    WHERE status NOT IN ('closed', 'verified');

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    subject     TEXT,
    outcome     TEXT NOT NULL,
    detail      TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log (at DESC);
"""


class ResultStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            row = conn.execute("SELECT version FROM schema_version").fetchone()
            if row is None:
                conn.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))

    # -- runs ---------------------------------------------------------------

    def save_run(self, run: Run) -> None:
        v = run.verdict
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO runs (run_id, scenario_id, target_id, profile, status,
                                  purple_verdict, prevention, detection, evidence, response,
                                  created_at, finished_at, scenario_digest, payload)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(run_id) DO UPDATE SET
                    status=excluded.status,
                    purple_verdict=excluded.purple_verdict,
                    prevention=excluded.prevention,
                    detection=excluded.detection,
                    evidence=excluded.evidence,
                    response=excluded.response,
                    finished_at=excluded.finished_at,
                    payload=excluded.payload
                """,
                (
                    run.run_id, run.scenario_id, run.target_id, run.profile, str(run.status),
                    str(v.purple_verdict) if v else None,
                    str(v.prevention) if v else None,
                    str(v.detection) if v else None,
                    str(v.evidence) if v else None,
                    str(v.response) if v else None,
                    run.created_at.isoformat(),
                    run.finished_at.isoformat() if run.finished_at else None,
                    run.scenario_digest,
                    run.model_dump_json(),
                ),
            )

    def get_run(self, run_id: str) -> Run:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT payload FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        if row is None:
            raise RunNotFound(f"unknown run '{run_id}'")
        return Run.model_validate_json(row["payload"])

    def list_runs(
        self,
        *,
        scenario_id: str | None = None,
        target_id: str | None = None,
        profile: str | None = None,
        verdict: str | None = None,
        limit: int = 50,
    ) -> list[Run]:
        clauses: list[str] = []
        params: list[Any] = []
        if scenario_id:
            clauses.append("scenario_id = ?")
            params.append(scenario_id)
        if target_id:
            clauses.append("target_id = ?")
            params.append(target_id)
        if profile:
            clauses.append("profile = ?")
            params.append(profile)
        if verdict:
            clauses.append("purple_verdict = ?")
            params.append(verdict)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT payload FROM runs {where} ORDER BY created_at DESC LIMIT ?",  # noqa: S608
                params,
            ).fetchall()
        return [Run.model_validate_json(r["payload"]) for r in rows]

    def latest_run_for(self, scenario_id: str, target_id: str) -> Run | None:
        runs = self.list_runs(scenario_id=scenario_id, target_id=target_id, limit=1)
        return runs[0] if runs else None

    # -- findings -----------------------------------------------------------

    def save_finding(self, finding: Finding) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO findings (finding_id, scenario_id, target_id, status, severity,
                                      verdict, first_seen_run, last_seen_run, updated_at, payload)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    status=excluded.status,
                    verdict=excluded.verdict,
                    last_seen_run=excluded.last_seen_run,
                    updated_at=excluded.updated_at,
                    payload=excluded.payload
                """,
                (
                    finding.finding_id, finding.scenario_id, finding.target_id,
                    str(finding.status), str(finding.severity), str(finding.verdict),
                    finding.first_seen_run, finding.last_seen_run,
                    finding.updated_at.isoformat(), finding.model_dump_json(),
                ),
            )

    def get_finding(self, finding_id: str) -> Finding:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT payload FROM findings WHERE finding_id = ?", (finding_id,)
            ).fetchone()
        if row is None:
            raise FindingNotFound(f"unknown finding '{finding_id}'")
        return Finding.model_validate_json(row["payload"])

    def find_open_finding(self, scenario_id: str, target_id: str) -> Finding | None:
        """The open finding for this scenario/target pair, if one exists.

        Used so a repeated failure updates the existing finding instead of
        spawning a new one on every nightly run.
        """
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT payload FROM findings
                WHERE scenario_id = ? AND target_id = ?
                  AND status NOT IN ('closed', 'verified', 'accepted_risk')
                ORDER BY updated_at DESC LIMIT 1
                """,
                (scenario_id, target_id),
            ).fetchone()
        return Finding.model_validate_json(row["payload"]) if row else None

    def list_findings(
        self, *, status: FindingStatus | None = None, limit: int = 100
    ) -> list[Finding]:
        with self._conn() as conn:
            if status:
                rows = conn.execute(
                    "SELECT payload FROM findings WHERE status = ? "
                    "ORDER BY updated_at DESC LIMIT ?",
                    (str(status), limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT payload FROM findings ORDER BY updated_at DESC LIMIT ?", (limit,)
                ).fetchall()
        return [Finding.model_validate_json(r["payload"]) for r in rows]

    # -- audit --------------------------------------------------------------

    def audit(
        self,
        *,
        actor: str,
        action: str,
        outcome: str,
        subject: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Append-only record of everything the gateway and CLI were asked to do.

        Refusals are logged too — a rejected request is exactly the thing you
        want to find later when asking what a model tried to do.
        """
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO audit_log (at, actor, action, subject, outcome, detail) "
                "VALUES (?,?,?,?,?,?)",
                (
                    datetime.now(UTC).isoformat(), actor, action, subject, outcome,
                    json.dumps(detail, default=str) if detail else None,
                ),
            )

    def audit_tail(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT at, actor, action, subject, outcome, detail FROM audit_log "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    # -- aggregates ---------------------------------------------------------

    def verdict_counts(self, *, target_id: str | None = None) -> dict[str, int]:
        """Verdict histogram over the latest run of each scenario.

        Counting every historical run would let a scenario that failed fifty
        times last month dominate today's picture.
        """
        params: list[Any] = []
        filter_sql = ""
        if target_id:
            filter_sql = "WHERE target_id = ?"
            params.append(target_id)

        with self._conn() as conn:
            rows = conn.execute(
                f"""
                SELECT purple_verdict, COUNT(*) AS n FROM (
                    SELECT scenario_id, target_id, purple_verdict,
                           ROW_NUMBER() OVER (
                               PARTITION BY scenario_id, target_id ORDER BY created_at DESC
                           ) AS rn
                    FROM runs {filter_sql}
                ) WHERE rn = 1 AND purple_verdict IS NOT NULL
                GROUP BY purple_verdict
                """,  # noqa: S608
                params,
            ).fetchall()
        return {r["purple_verdict"]: r["n"] for r in rows}
