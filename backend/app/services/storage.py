from __future__ import annotations
import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional


class SQLiteStore:
    """Small durable store used by the offline-first MVP.

    The schema is additive on purpose so existing hackathon databases survive
    upgrades without an external migration dependency.
    """

    def __init__(self) -> None:
        configured = os.getenv("TRUSTKERNEL_DB_PATH")
        if configured:
            self.path = configured
        else:
            data_dir = Path(__file__).resolve().parents[2] / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            self.path = str(data_dir / "trustkernel.db")
        self._lock = threading.RLock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _init_schema(self) -> None:
        with self._lock, self._connect() as db:
            db.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS audit_entries (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT UNIQUE NOT NULL,
                    timestamp REAL NOT NULL,
                    prev_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    audit_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    resolved_at REAL,
                    resolution TEXT,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS agents (
                    id TEXT PRIMARY KEY,
                    data_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS workspaces (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    api_key_hash TEXT UNIQUE NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS workspace_keys (
                    id TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL,
                    key_hash TEXT UNIQUE NOT NULL,
                    key_prefix TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    revoked_at REAL,
                    FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
                );
                CREATE INDEX IF NOT EXISTS idx_workspace_keys_hash ON workspace_keys(key_hash);
                CREATE INDEX IF NOT EXISTS idx_workspace_keys_ws ON workspace_keys(workspace_id);

                CREATE TABLE IF NOT EXISTS workspace_members (
                    id TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL,
                    email TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    UNIQUE(workspace_id, email),
                    FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
                );
                CREATE INDEX IF NOT EXISTS idx_workspace_members_ws ON workspace_members(workspace_id);

                CREATE TABLE IF NOT EXISTS approval_groups (
                    id TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    roles_json TEXT NOT NULL,
                    members_json TEXT NOT NULL,
                    min_approvals INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    UNIQUE(workspace_id, name),
                    FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
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
                    created_at REAL NOT NULL,
                    UNIQUE(profile, version, sha256)
                );
                CREATE INDEX IF NOT EXISTS idx_policy_bundles_profile ON policy_bundles(profile, created_at DESC);

                CREATE TABLE IF NOT EXISTS workspace_policy_bindings (
                    workspace_id TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    bundle_id TEXT NOT NULL,
                    activated_by TEXT NOT NULL,
                    activated_at REAL NOT NULL,
                    PRIMARY KEY(workspace_id, profile),
                    FOREIGN KEY(workspace_id) REFERENCES workspaces(id),
                    FOREIGN KEY(bundle_id) REFERENCES policy_bundles(id)
                );

                CREATE TABLE IF NOT EXISTS mcp_servers (
                    id TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    canonical_uri TEXT NOT NULL,
                    issuer TEXT,
                    manifest_sha256 TEXT NOT NULL,
                    allowed_scopes_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    UNIQUE(workspace_id, canonical_uri),
                    FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
                );
                CREATE INDEX IF NOT EXISTS idx_mcp_servers_ws ON mcp_servers(workspace_id);

                CREATE TABLE IF NOT EXISTS message_nonces (
                    nonce TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL,
                    sender_id TEXT NOT NULL,
                    seen_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_message_nonces_expiry ON message_nonces(expires_at);

                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    audit_id TEXT UNIQUE NOT NULL,
                    workspace_id TEXT,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    title TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_incidents_ws ON incidents(workspace_id);
                CREATE TABLE IF NOT EXISTS telemetry_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    event_name TEXT NOT NULL,
                    workspace_id TEXT,
                    agent_id TEXT,
                    attributes_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_telemetry_ws ON telemetry_events(workspace_id);

                CREATE TABLE IF NOT EXISTS member_sessions (
                    jti TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL,
                    email TEXT NOT NULL,
                    role TEXT NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked_at REAL,
                    FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
                );
                CREATE INDEX IF NOT EXISTS idx_member_sessions_ws ON member_sessions(workspace_id, email);
                CREATE INDEX IF NOT EXISTS idx_member_sessions_exp ON member_sessions(expires_at);

                CREATE TABLE IF NOT EXISTS policy_change_requests (
                    id TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    bundle_id TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    approval_group TEXT NOT NULL,
                    status TEXT NOT NULL,
                    diff_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    activated_at REAL,
                    FOREIGN KEY(workspace_id) REFERENCES workspaces(id),
                    FOREIGN KEY(bundle_id) REFERENCES policy_bundles(id)
                );
                CREATE INDEX IF NOT EXISTS idx_policy_changes_ws ON policy_change_requests(workspace_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS workload_identity_keys (
                    id TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    revoked_at REAL,
                    UNIQUE(workspace_id, fingerprint),
                    FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
                );
                CREATE INDEX IF NOT EXISTS idx_workload_keys_agent ON workload_identity_keys(workspace_id, agent_id);

                CREATE TABLE IF NOT EXISTS policy_change_votes (
                    request_id TEXT NOT NULL,
                    actor_email TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY(request_id, actor_email),
                    FOREIGN KEY(request_id) REFERENCES policy_change_requests(id)
                );
                """
            )

    def ping(self) -> bool:
        try:
            with self._lock, self._connect() as db:
                return db.execute("SELECT 1").fetchone()[0] == 1
        except sqlite3.Error:
            return False

    def append_audit(self, entry: Dict[str, Any]) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT INTO audit_entries(id,timestamp,prev_hash,payload_json,hash) VALUES(?,?,?,?,?)",
                (entry["id"], entry["timestamp"], entry["prev_hash"], json.dumps(entry["payload"], default=str), entry["hash"]),
            )

    def audit_entries(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT id,timestamp,prev_hash,payload_json,hash FROM audit_entries ORDER BY seq ASC").fetchall()
        return [{"id": r["id"], "timestamp": r["timestamp"], "prev_hash": r["prev_hash"], "payload": json.loads(r["payload_json"]), "hash": r["hash"]} for r in rows]

    def create_approval(self, item: Dict[str, Any]) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO approvals
                (audit_id,status,created_at,resolved_at,resolution,payload_json)
                VALUES(?,?,?,?,?,?)""",
                (item["audit_id"], item["status"], item["created_at"], item["resolved_at"], item["resolution"], json.dumps(item["payload"], default=str)),
            )

    def update_approval(self, item: Dict[str, Any]) -> None:
        self.create_approval(item)

    def get_approval(self, audit_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM approvals WHERE audit_id=?", (audit_id,)).fetchone()
        return self._approval_row(row) if row else None

    def approvals(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT * FROM approvals ORDER BY created_at DESC").fetchall()
        return [self._approval_row(row) for row in rows]

    @staticmethod
    def _approval_row(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "audit_id": row["audit_id"], "status": row["status"], "created_at": row["created_at"],
            "resolved_at": row["resolved_at"], "resolution": row["resolution"], "payload": json.loads(row["payload_json"]),
        }

    def upsert_agent(self, agent_id: str, data: Dict[str, Any]) -> None:
        with self._lock, self._connect() as db:
            db.execute("INSERT OR REPLACE INTO agents(id,data_json) VALUES(?,?)", (agent_id, json.dumps(data, default=str)))

    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT data_json FROM agents WHERE id=?", (agent_id,)).fetchone()
        return json.loads(row["data_json"]) if row else None

    def agents(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT data_json FROM agents ORDER BY id").fetchall()
        return [json.loads(row["data_json"]) for row in rows]

    def create_workspace(self, workspace_id: str, name: str, api_key_hash: str, created_at: float) -> None:
        with self._lock, self._connect() as db:
            db.execute("INSERT INTO workspaces(id,name,api_key_hash,created_at) VALUES(?,?,?,?)", (workspace_id, name, api_key_hash, created_at))

    def workspace(self, workspace_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT id,name,created_at FROM workspaces WHERE id=?", (workspace_id,)).fetchone()
        return dict(row) if row else None

    def workspace_by_legacy_key_hash(self, api_key_hash: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT id,name,created_at FROM workspaces WHERE api_key_hash=?", (api_key_hash,)).fetchone()
        return dict(row) if row else None

    def workspaces(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT id,name,created_at FROM workspaces ORDER BY created_at DESC").fetchall()
        return [dict(row) for row in rows]

    def create_workspace_key(self, item: Dict[str, Any]) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT INTO workspace_keys(id,workspace_id,key_hash,key_prefix,created_at,revoked_at) VALUES(?,?,?,?,?,?)",
                (item["id"], item["workspace_id"], item["key_hash"], item["key_prefix"], item["created_at"], item.get("revoked_at")),
            )

    def workspace_key_by_hash(self, key_hash: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            row = db.execute(
                """SELECT k.id AS key_id,k.workspace_id,k.key_prefix,k.created_at,k.revoked_at,w.name
                   FROM workspace_keys k JOIN workspaces w ON w.id=k.workspace_id
                   WHERE k.key_hash=?""", (key_hash,),
            ).fetchone()
        return dict(row) if row else None

    def workspace_keys(self, workspace_id: str) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute(
                "SELECT id,workspace_id,key_prefix,created_at,revoked_at FROM workspace_keys WHERE workspace_id=? ORDER BY created_at DESC",
                (workspace_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def revoke_workspace_key(self, workspace_id: str, key_id: str, revoked_at: float) -> bool:
        with self._lock, self._connect() as db:
            cur = db.execute(
                "UPDATE workspace_keys SET revoked_at=? WHERE id=? AND workspace_id=? AND revoked_at IS NULL",
                (revoked_at, key_id, workspace_id),
            )
        return cur.rowcount > 0

    def upsert_workspace_member(self, item: Dict[str, Any]) -> None:
        with self._lock, self._connect() as db:
            existing = db.execute("SELECT id,created_at FROM workspace_members WHERE workspace_id=? AND email=?", (item["workspace_id"], item["email"])).fetchone()
            if existing:
                db.execute("UPDATE workspace_members SET role=?,updated_at=? WHERE id=?", (item["role"], item["updated_at"], existing["id"]))
            else:
                db.execute(
                    "INSERT INTO workspace_members(id,workspace_id,email,role,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                    (item["id"], item["workspace_id"], item["email"], item["role"], item["created_at"], item["updated_at"]),
                )

    def workspace_member(self, workspace_id: str, email: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM workspace_members WHERE workspace_id=? AND email=?", (workspace_id, email)).fetchone()
        return dict(row) if row else None

    def workspace_members(self, workspace_id: str) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT * FROM workspace_members WHERE workspace_id=? ORDER BY created_at", (workspace_id,)).fetchall()
        return [dict(row) for row in rows]

    def upsert_approval_group(self, item: Dict[str, Any]) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO approval_groups
                (id,workspace_id,name,roles_json,members_json,min_approvals,created_at)
                VALUES(?,?,?,?,?,?,?)""",
                (item["id"], item["workspace_id"], item["name"], json.dumps(item["roles"]), json.dumps(item["members"]), item["min_approvals"], item["created_at"]),
            )

    def approval_group(self, workspace_id: str, name: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM approval_groups WHERE workspace_id=? AND name=?", (workspace_id, name)).fetchone()
        return self._approval_group_row(row) if row else None

    def approval_groups(self, workspace_id: str) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT * FROM approval_groups WHERE workspace_id=? ORDER BY name", (workspace_id,)).fetchall()
        return [self._approval_group_row(row) for row in rows]

    @staticmethod
    def _approval_group_row(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"], "workspace_id": row["workspace_id"], "name": row["name"],
            "roles": json.loads(row["roles_json"]), "members": json.loads(row["members_json"]),
            "min_approvals": row["min_approvals"], "created_at": row["created_at"],
        }

    def create_policy_bundle(self, item: Dict[str, Any]) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                """INSERT OR IGNORE INTO policy_bundles
                (id,profile,version,sha256,signature,policy_json,source,created_by,created_at)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (item["id"], item["profile"], item["version"], item["sha256"], item["signature"], json.dumps(item["policy"], sort_keys=True), item["source"], item["created_by"], item["created_at"]),
            )

    def policy_bundle(self, bundle_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM policy_bundles WHERE id=?", (bundle_id,)).fetchone()
        return self._policy_bundle_row(row) if row else None

    def policy_bundles(self, profile: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            if profile:
                rows = db.execute("SELECT * FROM policy_bundles WHERE profile=? ORDER BY created_at DESC", (profile,)).fetchall()
            else:
                rows = db.execute("SELECT * FROM policy_bundles ORDER BY created_at DESC").fetchall()
        return [self._policy_bundle_row(row) for row in rows]

    @staticmethod
    def _policy_bundle_row(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"], "profile": row["profile"], "version": row["version"], "sha256": row["sha256"],
            "signature": row["signature"], "policy": json.loads(row["policy_json"]), "source": row["source"],
            "created_by": row["created_by"], "created_at": row["created_at"],
        }

    def bind_policy_bundle(self, workspace_id: str, profile: str, bundle_id: str, activated_by: str, activated_at: float) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                """INSERT INTO workspace_policy_bindings(workspace_id,profile,bundle_id,activated_by,activated_at)
                VALUES(?,?,?,?,?) ON CONFLICT(workspace_id,profile) DO UPDATE SET
                bundle_id=excluded.bundle_id,activated_by=excluded.activated_by,activated_at=excluded.activated_at""",
                (workspace_id, profile, bundle_id, activated_by, activated_at),
            )

    def policy_binding(self, workspace_id: str, profile: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM workspace_policy_bindings WHERE workspace_id=? AND profile=?", (workspace_id, profile)).fetchone()
        return dict(row) if row else None

    def upsert_mcp_server(self, item: Dict[str, Any]) -> None:
        with self._lock, self._connect() as db:
            existing = db.execute("SELECT id,created_at FROM mcp_servers WHERE workspace_id=? AND canonical_uri=?", (item["workspace_id"], item["canonical_uri"])).fetchone()
            if existing:
                db.execute(
                    """UPDATE mcp_servers SET name=?,issuer=?,manifest_sha256=?,allowed_scopes_json=?,status=?,updated_at=? WHERE id=?""",
                    (item["name"], item.get("issuer"), item["manifest_sha256"], json.dumps(item["allowed_scopes"]), item["status"], item["updated_at"], existing["id"]),
                )
            else:
                db.execute(
                    """INSERT INTO mcp_servers(id,workspace_id,name,canonical_uri,issuer,manifest_sha256,allowed_scopes_json,status,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (item["id"], item["workspace_id"], item["name"], item["canonical_uri"], item.get("issuer"), item["manifest_sha256"], json.dumps(item["allowed_scopes"]), item["status"], item["created_at"], item["updated_at"]),
                )

    def mcp_server(self, workspace_id: str, server_id: Optional[str] = None, canonical_uri: Optional[str] = None) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            if server_id:
                row = db.execute("SELECT * FROM mcp_servers WHERE workspace_id=? AND id=?", (workspace_id, server_id)).fetchone()
            else:
                row = db.execute("SELECT * FROM mcp_servers WHERE workspace_id=? AND canonical_uri=?", (workspace_id, canonical_uri)).fetchone()
        return self._mcp_row(row) if row else None

    def mcp_servers(self, workspace_id: str) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT * FROM mcp_servers WHERE workspace_id=? ORDER BY name", (workspace_id,)).fetchall()
        return [self._mcp_row(row) for row in rows]

    @staticmethod
    def _mcp_row(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"], "workspace_id": row["workspace_id"], "name": row["name"],
            "canonical_uri": row["canonical_uri"], "issuer": row["issuer"], "manifest_sha256": row["manifest_sha256"],
            "allowed_scopes": json.loads(row["allowed_scopes_json"]), "status": row["status"],
            "created_at": row["created_at"], "updated_at": row["updated_at"],
        }

    def nonce_seen(self, nonce: str, now: float) -> bool:
        with self._lock, self._connect() as db:
            db.execute("DELETE FROM message_nonces WHERE expires_at < ?", (now,))
            row = db.execute("SELECT nonce FROM message_nonces WHERE nonce=?", (nonce,)).fetchone()
        return row is not None

    def record_nonce(self, nonce: str, workspace_id: str, sender_id: str, seen_at: float, expires_at: float) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO message_nonces(nonce,workspace_id,sender_id,seen_at,expires_at) VALUES(?,?,?,?,?)",
                (nonce, workspace_id, sender_id, seen_at, expires_at),
            )

    def create_incident(self, item: Dict[str, Any]) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO incidents
                (id,audit_id,workspace_id,severity,status,title,created_at,updated_at,payload_json)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (item["id"], item["audit_id"], item.get("workspace_id"), item["severity"], item["status"], item["title"], item["created_at"], item["updated_at"], json.dumps(item["payload"], default=str)),
            )

    def incidents(self, workspace_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            if workspace_id:
                rows = db.execute("SELECT * FROM incidents WHERE workspace_id=? ORDER BY created_at DESC", (workspace_id,)).fetchall()
            else:
                rows = db.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
        return [self._incident_row(row) for row in rows]

    def incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return self._incident_row(row) if row else None

    def update_incident_status(self, incident_id: str, status: str, updated_at: float) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            db.execute("UPDATE incidents SET status=?,updated_at=? WHERE id=?", (status, updated_at, incident_id))
        return self.incident(incident_id)

    @staticmethod
    def _incident_row(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"], "audit_id": row["audit_id"], "workspace_id": row["workspace_id"],
            "severity": row["severity"], "status": row["status"], "title": row["title"],
            "created_at": row["created_at"], "updated_at": row["updated_at"], "payload": json.loads(row["payload_json"]),
        }

    def create_member_session(self, item: Dict[str, Any]) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT INTO member_sessions(jti,workspace_id,email,role,issued_at,expires_at,revoked_at) VALUES(?,?,?,?,?,?,?)",
                (item["jti"], item["workspace_id"], item["email"], item["role"], item["issued_at"], item["expires_at"], item.get("revoked_at")),
            )

    def member_session(self, jti: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM member_sessions WHERE jti=?", (jti,)).fetchone()
        return dict(row) if row else None

    def revoke_member_session(self, jti: str, revoked_at: float) -> bool:
        with self._lock, self._connect() as db:
            cur = db.execute("UPDATE member_sessions SET revoked_at=? WHERE jti=? AND revoked_at IS NULL", (revoked_at, jti))
        return cur.rowcount > 0

    def member_sessions(self, workspace_id: str, email: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            if email:
                rows = db.execute("SELECT * FROM member_sessions WHERE workspace_id=? AND email=? ORDER BY issued_at DESC", (workspace_id, email)).fetchall()
            else:
                rows = db.execute("SELECT * FROM member_sessions WHERE workspace_id=? ORDER BY issued_at DESC", (workspace_id,)).fetchall()
        return [dict(row) for row in rows]

    def create_workload_key(self, item: Dict[str, Any]) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                """INSERT INTO workload_identity_keys
                (id,workspace_id,agent_id,algorithm,public_key_pem,fingerprint,status,created_at,revoked_at)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (item["id"], item["workspace_id"], item["agent_id"], item["algorithm"], item["public_key_pem"], item["fingerprint"], item["status"], item["created_at"], item.get("revoked_at")),
            )

    def workload_key(self, workspace_id: str, key_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM workload_identity_keys WHERE workspace_id=? AND id=?", (workspace_id, key_id)).fetchone()
        return dict(row) if row else None

    def workload_keys(self, workspace_id: str, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            if agent_id:
                rows = db.execute("SELECT * FROM workload_identity_keys WHERE workspace_id=? AND agent_id=? ORDER BY created_at DESC", (workspace_id, agent_id)).fetchall()
            else:
                rows = db.execute("SELECT * FROM workload_identity_keys WHERE workspace_id=? ORDER BY created_at DESC", (workspace_id,)).fetchall()
        return [dict(row) for row in rows]

    def revoke_workload_key(self, workspace_id: str, key_id: str, revoked_at: float) -> bool:
        with self._lock, self._connect() as db:
            cur = db.execute("UPDATE workload_identity_keys SET status='REVOKED',revoked_at=? WHERE workspace_id=? AND id=? AND status!='REVOKED'", (revoked_at, workspace_id, key_id))
        return cur.rowcount > 0

    def create_policy_change(self, item: Dict[str, Any]) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                """INSERT INTO policy_change_requests
                (id,workspace_id,profile,bundle_id,requested_by,approval_group,status,diff_json,created_at,updated_at,activated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (item["id"], item["workspace_id"], item["profile"], item["bundle_id"], item["requested_by"], item["approval_group"], item["status"], json.dumps(item["diff"], default=str), item["created_at"], item["updated_at"], item.get("activated_at")),
            )

    def policy_change(self, request_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM policy_change_requests WHERE id=?", (request_id,)).fetchone()
        return self._policy_change_row(row) if row else None

    def policy_changes(self, workspace_id: str) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT * FROM policy_change_requests WHERE workspace_id=? ORDER BY created_at DESC", (workspace_id,)).fetchall()
        return [self._policy_change_row(row) for row in rows]

    def update_policy_change(self, request_id: str, *, status: str, updated_at: float, activated_at: Optional[float] = None) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            db.execute("UPDATE policy_change_requests SET status=?,updated_at=?,activated_at=COALESCE(?,activated_at) WHERE id=?", (status, updated_at, activated_at, request_id))
        return self.policy_change(request_id)

    @staticmethod
    def _policy_change_row(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"], "workspace_id": row["workspace_id"], "profile": row["profile"],
            "bundle_id": row["bundle_id"], "requested_by": row["requested_by"],
            "approval_group": row["approval_group"], "status": row["status"],
            "diff": json.loads(row["diff_json"]), "created_at": row["created_at"],
            "updated_at": row["updated_at"], "activated_at": row["activated_at"],
        }

    def upsert_policy_change_vote(self, request_id: str, actor_email: str, decision: str, created_at: float) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                """INSERT INTO policy_change_votes(request_id,actor_email,decision,created_at) VALUES(?,?,?,?)
                ON CONFLICT(request_id,actor_email) DO UPDATE SET decision=excluded.decision,created_at=excluded.created_at""",
                (request_id, actor_email, decision, created_at),
            )

    def policy_change_votes(self, request_id: str) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT * FROM policy_change_votes WHERE request_id=? ORDER BY created_at", (request_id,)).fetchall()
        return [dict(row) for row in rows]

    def append_telemetry(self, timestamp: float, event_name: str, workspace_id: Optional[str], agent_id: Optional[str], attributes: Dict[str, Any]) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT INTO telemetry_events(timestamp,event_name,workspace_id,agent_id,attributes_json) VALUES(?,?,?,?,?)",
                (timestamp, event_name, workspace_id, agent_id, json.dumps(attributes, default=str)),
            )

    def telemetry(self, workspace_id: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            if workspace_id:
                rows = db.execute("SELECT * FROM telemetry_events WHERE workspace_id=? ORDER BY seq DESC LIMIT ?", (workspace_id, limit)).fetchall()
            else:
                rows = db.execute("SELECT * FROM telemetry_events ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
        return [{"timestamp": r["timestamp"], "event_name": r["event_name"], "workspace_id": r["workspace_id"], "agent_id": r["agent_id"], "attributes": json.loads(r["attributes_json"])} for r in rows]


store = SQLiteStore()
