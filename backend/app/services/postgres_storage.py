from __future__ import annotations

import hashlib
import os
import re
import threading
from dataclasses import dataclass
from typing import Any, Iterable

from .storage import SQLiteStore


@dataclass(frozen=True)
class Migration:
    version: str
    sql: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode("utf-8")).hexdigest()


POSTGRES_SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    checksum TEXT NOT NULL,
    applied_at DOUBLE PRECISION NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
);
CREATE TABLE IF NOT EXISTS audit_entries (
    seq BIGSERIAL PRIMARY KEY,
    id TEXT UNIQUE NOT NULL,
    timestamp DOUBLE PRECISION NOT NULL,
    prev_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
    audit_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    resolved_at DOUBLE PRECISION,
    resolution TEXT,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, data_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    api_key_hash TEXT UNIQUE NOT NULL,
    created_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS workspace_keys (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    key_hash TEXT UNIQUE NOT NULL,
    key_prefix TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    revoked_at DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_workspace_keys_hash ON workspace_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_workspace_keys_ws ON workspace_keys(workspace_id);
CREATE TABLE IF NOT EXISTS workspace_members (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL,
    UNIQUE(workspace_id, email)
);
CREATE INDEX IF NOT EXISTS idx_workspace_members_ws ON workspace_members(workspace_id);
CREATE TABLE IF NOT EXISTS approval_groups (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    name TEXT NOT NULL,
    roles_json TEXT NOT NULL,
    members_json TEXT NOT NULL,
    min_approvals INTEGER NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    UNIQUE(workspace_id, name)
);
CREATE INDEX IF NOT EXISTS idx_approval_groups_ws ON approval_groups(workspace_id);
CREATE TABLE IF NOT EXISTS policy_bundles (
    id TEXT PRIMARY KEY,
    profile TEXT NOT NULL,
    version INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    signature TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    source TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    UNIQUE(profile, version, sha256)
);
CREATE INDEX IF NOT EXISTS idx_policy_bundles_profile ON policy_bundles(profile, created_at DESC);
CREATE TABLE IF NOT EXISTS workspace_policy_bindings (
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    profile TEXT NOT NULL,
    bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    activated_by TEXT NOT NULL,
    activated_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY(workspace_id, profile)
);
CREATE TABLE IF NOT EXISTS mcp_servers (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    name TEXT NOT NULL,
    canonical_uri TEXT NOT NULL,
    issuer TEXT,
    manifest_sha256 TEXT NOT NULL,
    allowed_scopes_json TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL,
    UNIQUE(workspace_id, canonical_uri)
);
CREATE INDEX IF NOT EXISTS idx_mcp_servers_ws ON mcp_servers(workspace_id);
CREATE TABLE IF NOT EXISTS message_nonces (
    nonce TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    seen_at DOUBLE PRECISION NOT NULL,
    expires_at DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_message_nonces_expiry ON message_nonces(expires_at);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    audit_id TEXT UNIQUE NOT NULL,
    workspace_id TEXT,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    title TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_ws ON incidents(workspace_id);
CREATE TABLE IF NOT EXISTS telemetry_events (
    seq BIGSERIAL PRIMARY KEY,
    timestamp DOUBLE PRECISION NOT NULL,
    event_name TEXT NOT NULL,
    workspace_id TEXT,
    agent_id TEXT,
    attributes_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_telemetry_ws ON telemetry_events(workspace_id);
CREATE TABLE IF NOT EXISTS member_sessions (
    jti TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    issued_at DOUBLE PRECISION NOT NULL,
    expires_at DOUBLE PRECISION NOT NULL,
    revoked_at DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_member_sessions_ws ON member_sessions(workspace_id, email);
CREATE INDEX IF NOT EXISTS idx_member_sessions_exp ON member_sessions(expires_at);
CREATE TABLE IF NOT EXISTS policy_change_requests (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    profile TEXT NOT NULL,
    bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    requested_by TEXT NOT NULL,
    approval_group TEXT NOT NULL,
    status TEXT NOT NULL,
    diff_json TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL,
    activated_at DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_policy_changes_ws ON policy_change_requests(workspace_id, created_at DESC);
CREATE TABLE IF NOT EXISTS workload_identity_keys (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    agent_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    revoked_at DOUBLE PRECISION,
    UNIQUE(workspace_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_workload_keys_agent ON workload_identity_keys(workspace_id, agent_id);
CREATE TABLE IF NOT EXISTS policy_change_votes (
    request_id TEXT NOT NULL REFERENCES policy_change_requests(id),
    actor_email TEXT NOT NULL,
    decision TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY(request_id, actor_email)
);
"""

MIGRATIONS = (Migration("0001_v14_baseline", POSTGRES_SCHEMA_V1),)


class CompatRow(dict):
    """Mapping row that also supports SQLite-style integer indexing."""

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


class CursorAdapter:
    def __init__(self, cursor: Any) -> None:
        self.cursor = cursor

    @property
    def rowcount(self) -> int:
        return self.cursor.rowcount

    def fetchone(self) -> CompatRow | None:
        row = self.cursor.fetchone()
        return CompatRow(row) if row is not None else None

    def fetchall(self) -> list[CompatRow]:
        return [CompatRow(row) for row in self.cursor.fetchall()]


_QMARK = re.compile(r"\?")


def _postgres_sql(sql: str) -> str:
    compact = " ".join(sql.split())
    if compact.startswith("INSERT OR REPLACE INTO approvals"):
        return """INSERT INTO approvals(audit_id,status,created_at,resolved_at,resolution,payload_json)
        VALUES(%s,%s,%s,%s,%s,%s)
        ON CONFLICT(audit_id) DO UPDATE SET status=EXCLUDED.status,created_at=EXCLUDED.created_at,
        resolved_at=EXCLUDED.resolved_at,resolution=EXCLUDED.resolution,payload_json=EXCLUDED.payload_json"""
    if compact.startswith("INSERT OR REPLACE INTO agents"):
        return "INSERT INTO agents(id,data_json) VALUES(%s,%s) ON CONFLICT(id) DO UPDATE SET data_json=EXCLUDED.data_json"
    if compact.startswith("INSERT OR REPLACE INTO approval_groups"):
        return """INSERT INTO approval_groups(id,workspace_id,name,roles_json,members_json,min_approvals,created_at)
        VALUES(%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT(workspace_id,name) DO UPDATE SET id=EXCLUDED.id,roles_json=EXCLUDED.roles_json,
        members_json=EXCLUDED.members_json,min_approvals=EXCLUDED.min_approvals,created_at=EXCLUDED.created_at"""
    if compact.startswith("INSERT OR REPLACE INTO incidents"):
        return """INSERT INTO incidents(id,audit_id,workspace_id,severity,status,title,created_at,updated_at,payload_json)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT(id) DO UPDATE SET audit_id=EXCLUDED.audit_id,workspace_id=EXCLUDED.workspace_id,
        severity=EXCLUDED.severity,status=EXCLUDED.status,title=EXCLUDED.title,created_at=EXCLUDED.created_at,
        updated_at=EXCLUDED.updated_at,payload_json=EXCLUDED.payload_json"""
    return _QMARK.sub("%s", sql)


class ConnectionAdapter:
    def __init__(self, dsn: str) -> None:
        import psycopg
        from psycopg.rows import dict_row

        self.connection = psycopg.connect(dsn, row_factory=dict_row)

    def __enter__(self) -> "ConnectionAdapter":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        try:
            if exc_type is None:
                self.connection.commit()
            else:
                self.connection.rollback()
        finally:
            self.connection.close()

    def execute(self, sql: str, params: Iterable[Any] | None = None) -> CursorAdapter:
        cursor = self.connection.execute(_postgres_sql(sql), tuple(params or ()))
        return CursorAdapter(cursor)


class PostgresStore(SQLiteStore):
    """PostgreSQL implementation preserving the existing storage service contract.

    The inherited CRUD methods intentionally stay unchanged; this adapter
    normalizes parameter binding and SQLite's handful of REPLACE statements.
    Migrations are checksum-pinned and fail closed on drift.
    """

    backend = "postgresql"

    def __init__(self) -> None:
        self.dsn = os.getenv("TRUSTKERNEL_DATABASE_URL", "").strip()
        if not self.dsn:
            raise RuntimeError("TRUSTKERNEL_DATABASE_URL is required when TRUSTKERNEL_DB_BACKEND=postgres")
        if not self.dsn.startswith(("postgresql://", "postgres://")):
            raise RuntimeError("TRUSTKERNEL_DATABASE_URL must be a PostgreSQL URL")
        self._lock = threading.RLock()
        self._init_schema()

    def _connect(self) -> ConnectionAdapter:
        return ConnectionAdapter(self.dsn)

    def _init_schema(self) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at DOUBLE PRECISION NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()))"
            )
            for migration in MIGRATIONS:
                existing = db.execute(
                    "SELECT checksum FROM schema_migrations WHERE version=?", (migration.version,)
                ).fetchone()
                if existing:
                    if existing["checksum"] != migration.checksum:
                        raise RuntimeError(f"database migration checksum drift for {migration.version}")
                    continue
                for statement in (part.strip() for part in migration.sql.split(";")):
                    if statement:
                        db.execute(statement)
                db.execute(
                    "INSERT INTO schema_migrations(version,checksum) VALUES(?,?)",
                    (migration.version, migration.checksum),
                )

    def ping(self) -> bool:
        try:
            with self._lock, self._connect() as db:
                return db.execute("SELECT 1 AS ok").fetchone()["ok"] == 1
        except Exception:
            return False

    def migration_status(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute(
                "SELECT version,checksum,applied_at FROM schema_migrations ORDER BY version"
            ).fetchall()
        return [dict(row) for row in rows]
