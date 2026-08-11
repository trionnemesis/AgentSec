"""Schema migration runner for the SQLite result store.

`SCHEMA_VERSION` moved from 1 to 2 when `run_counter` was added (#12), but the
version row was only ever written when absent -- so a database created under
1 kept reporting 1 forever, regardless of what its actual tables looked like.
These tests pin the fix (#44): a stale version is upgraded and the row
corrected, migrations are idempotent, and a future version this build does
not recognise is refused rather than silently accepted.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agentsec.store.sqlite import SCHEMA_VERSION, ResultStore, SchemaVersionError

#: The tables the version-1 schema shipped with, before `run_counter` existed.
_V1_SCHEMA = """
CREATE TABLE schema_version (version INTEGER NOT NULL);
INSERT INTO schema_version (version) VALUES (1);

CREATE TABLE runs (
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

CREATE TABLE findings (
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

CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    subject     TEXT,
    outcome     TEXT NOT NULL,
    detail      TEXT
);
"""


def _make_v1_database(path: Path) -> None:
    """Build a database in exactly the pre-#12 v1 shape: no `run_counter`."""
    conn = sqlite3.connect(path)
    try:
        conn.executescript(_V1_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def _stored_version(path: Path) -> int:
    conn = sqlite3.connect(path)
    try:
        row = conn.execute("SELECT version FROM schema_version").fetchone()
        assert row is not None
        return int(row[0])
    finally:
        conn.close()


def _has_table(path: Path, name: str) -> bool:
    conn = sqlite3.connect(path)
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def test_a_fresh_database_lands_directly_on_the_current_version(tmp_path: Path) -> None:
    db_path = tmp_path / "fresh.db"

    ResultStore(db_path)

    assert _stored_version(db_path) == SCHEMA_VERSION
    assert _has_table(db_path, "run_counter")


def test_a_v1_database_is_upgraded_to_v2_on_open(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    _make_v1_database(db_path)
    assert not _has_table(db_path, "run_counter")
    assert _stored_version(db_path) == 1

    ResultStore(db_path)

    assert _stored_version(db_path) == SCHEMA_VERSION
    assert _has_table(db_path, "run_counter")


def test_reopening_an_already_migrated_database_is_a_no_op(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    _make_v1_database(db_path)

    ResultStore(db_path)
    assert _stored_version(db_path) == SCHEMA_VERSION

    # Second open must not fail, duplicate the migration, or move the version
    # again -- CREATE TABLE without IF NOT EXISTS would raise here if the
    # migration re-ran instead of recognising it already applied.
    ResultStore(db_path)
    assert _stored_version(db_path) == SCHEMA_VERSION


def test_a_future_schema_version_is_refused_rather_than_silently_opened(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "from_the_future.db"
    _make_v1_database(db_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION + 1,))
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(SchemaVersionError):
        ResultStore(db_path)

    # Refusal must not have rewritten the version row to make the problem
    # disappear on the next attempt.
    assert _stored_version(db_path) == SCHEMA_VERSION + 1
