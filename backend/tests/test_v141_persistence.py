from __future__ import annotations

import os

import pytest

from app.services.postgres_storage import (
    MIGRATIONS,
    MIGRATION_LOCK_KEY,
    MAX_MIGRATION_LOCK_TIMEOUT_MS,
    _migration_lock_timeout_ms,
    _postgres_sql,
)
from app.services.persistence import persistence_status


def test_sqlite_remains_default_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TRUSTKERNEL_DB_BACKEND", raising=False)
    status = persistence_status()
    assert status["backend"] == "sqlite"
    assert status["mode"] == "offline"


def test_postgres_migration_is_checksum_pinned() -> None:
    assert MIGRATIONS
    migration = MIGRATIONS[0]
    assert migration.version == "0001_v14_baseline"
    assert len(migration.checksum) == 64
    assert "schema_migrations" in migration.sql
    assert "workload_identity_keys" in migration.sql
    assert "policy_change_votes" in migration.sql


def test_qmark_parameters_are_normalized_for_psycopg() -> None:
    sql = _postgres_sql("SELECT * FROM workspace_members WHERE workspace_id=? AND email=?")
    assert sql.count("%s") == 2
    assert "?" not in sql


def test_sqlite_replace_upserts_are_rewritten_for_postgres() -> None:
    approvals = _postgres_sql(
        "INSERT OR REPLACE INTO approvals (audit_id,status,created_at,resolved_at,resolution,payload_json) VALUES(?,?,?,?,?,?)"
    )
    agents = _postgres_sql("INSERT OR REPLACE INTO agents(id,data_json) VALUES(?,?)")
    incidents = _postgres_sql(
        "INSERT OR REPLACE INTO incidents (id,audit_id,workspace_id,severity,status,title,created_at,updated_at,payload_json) VALUES(?,?,?,?,?,?,?,?,?)"
    )
    assert "ON CONFLICT(audit_id)" in approvals
    assert "ON CONFLICT(id)" in agents
    assert "ON CONFLICT(id)" in incidents


def test_postgres_backend_requires_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTKERNEL_DB_BACKEND", "postgres")
    monkeypatch.delenv("TRUSTKERNEL_DATABASE_URL", raising=False)
    from app.services.postgres_storage import PostgresStore

    with pytest.raises(RuntimeError, match="TRUSTKERNEL_DATABASE_URL"):
        PostgresStore()


def test_migration_lock_key_is_stable_signed_bigint() -> None:
    assert isinstance(MIGRATION_LOCK_KEY, int)
    assert -(2**63) <= MIGRATION_LOCK_KEY < 2**63
    assert MIGRATION_LOCK_KEY == -174185308204994466


def test_migration_lock_timeout_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TRUSTKERNEL_MIGRATION_LOCK_TIMEOUT_MS", raising=False)
    assert _migration_lock_timeout_ms() == 15_000

    monkeypatch.setenv("TRUSTKERNEL_MIGRATION_LOCK_TIMEOUT_MS", "25000")
    assert _migration_lock_timeout_ms() == 25_000

    monkeypatch.setenv("TRUSTKERNEL_MIGRATION_LOCK_TIMEOUT_MS", "999")
    with pytest.raises(RuntimeError, match="between 1000"):
        _migration_lock_timeout_ms()

    monkeypatch.setenv("TRUSTKERNEL_MIGRATION_LOCK_TIMEOUT_MS", str(MAX_MIGRATION_LOCK_TIMEOUT_MS + 1))
    with pytest.raises(RuntimeError, match="between 1000"):
        _migration_lock_timeout_ms()

    monkeypatch.setenv("TRUSTKERNEL_MIGRATION_LOCK_TIMEOUT_MS", "not-a-number")
    with pytest.raises(RuntimeError, match="must be an integer"):
        _migration_lock_timeout_ms()
