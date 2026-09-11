from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional

from .approval_groups import approval_groups
from .mcp_registry import mcp_registry
from .members import members
from .storage import store


def _canonical(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


class MCPRegistryGovernance:
    """Four-eyes change control for the trusted MCP registry.

    The registry is part of TrustKernel's trust boundary. This service keeps a
    signed proposal/evidence record and applies changes only after a distinct
    authorized approver accepts them.
    """

    def __init__(self) -> None:
        self.key = os.getenv("TRUSTKERNEL_MCP_GOVERNANCE_KEY", os.getenv("TRUSTKERNEL_POLICY_SIGNING_KEY", "trustkernel-dev-policy-signing-key")).encode("utf-8")
        self._init_schema()

    def _init_schema(self) -> None:
        with store._lock, store._connect() as db:  # shared MVP database/lock
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS mcp_registry_change_requests (
                    id TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    approval_group TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    applied_at REAL
                );
                CREATE INDEX IF NOT EXISTS idx_mcp_registry_changes_ws
                    ON mcp_registry_change_requests(workspace_id, created_at DESC);
                CREATE TABLE IF NOT EXISTS mcp_registry_change_votes (
                    request_id TEXT NOT NULL,
                    actor_email TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY(request_id, actor_email)
                );
                """
            )

    def _sign(self, workspace_id: str, request_id: str, sha256: str, requested_by: str) -> str:
        body = f"{workspace_id}|{request_id}|{sha256}|{requested_by.lower()}".encode("utf-8")
        return hmac.new(self.key, body, hashlib.sha256).hexdigest()

    def propose(
        self,
        workspace_id: str,
        *,
        requested_by: str,
        name: str,
        canonical_uri: str,
        manifest: str = "",
        manifest_sha256: str | None = None,
        issuer: str | None = None,
        allowed_scopes: List[str] | None = None,
        status: str = "ACTIVE",
        approval_group: str = "security-approvers",
    ) -> Dict[str, Any]:
        actor = requested_by.strip().lower()
        if not members.can(workspace_id, actor, "mcp.manage"):
            raise PermissionError("Actor cannot propose MCP registry changes")
        request_id = f"mcr_{uuid.uuid4().hex[:12]}"
        payload = {
            "name": name,
            "canonical_uri": canonical_uri.rstrip("/"),
            "manifest": manifest,
            "manifest_sha256": manifest_sha256,
            "issuer": issuer,
            "allowed_scopes": sorted(set(allowed_scopes or [])),
            "status": status.upper(),
        }
        sha256 = hashlib.sha256(_canonical(payload)).hexdigest()
        signature = self._sign(workspace_id, request_id, sha256, actor)
        now = time.time()
        with store._lock, store._connect() as db:
            db.execute(
                """INSERT INTO mcp_registry_change_requests
                   (id,workspace_id,requested_by,approval_group,status,payload_json,payload_sha256,signature,created_at,updated_at,applied_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (request_id, workspace_id, actor, approval_group, "PENDING", json.dumps(payload), sha256, signature, now, now, None),
            )
        return self.get(request_id) or {}

    def _votes(self, request_id: str) -> List[Dict[str, Any]]:
        with store._lock, store._connect() as db:
            rows = db.execute(
                "SELECT actor_email,decision,created_at FROM mcp_registry_change_votes WHERE request_id=? ORDER BY created_at",
                (request_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get(self, request_id: str) -> Optional[Dict[str, Any]]:
        with store._lock, store._connect() as db:
            row = db.execute("SELECT * FROM mcp_registry_change_requests WHERE id=?", (request_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json"))
        expected = self._sign(item["workspace_id"], item["id"], item["payload_sha256"], item["requested_by"])
        item["signature_valid"] = hmac.compare_digest(expected, item["signature"])
        item["payload_hash_valid"] = hashlib.sha256(_canonical(item["payload"])).hexdigest() == item["payload_sha256"]
        item["votes"] = self._votes(request_id)
        group = approval_groups.get(item["workspace_id"], item["approval_group"])
        item["required_approvals"] = max(1, int(group.get("min_approvals", 1)) if group else 1)
        item["approval_count"] = len({
            vote["actor_email"].lower()
            for vote in item["votes"]
            if vote["decision"] == "APPROVE" and vote["actor_email"].lower() != item["requested_by"].lower()
        })
        return item

    def list(self, workspace_id: str) -> List[Dict[str, Any]]:
        with store._lock, store._connect() as db:
            rows = db.execute(
                "SELECT id FROM mcp_registry_change_requests WHERE workspace_id=? ORDER BY created_at DESC",
                (workspace_id,),
            ).fetchall()
        return [self.get(row["id"]) for row in rows if self.get(row["id"]) is not None]

    def vote(self, request_id: str, actor_email: str, decision: str) -> Dict[str, Any]:
        item = self.get(request_id)
        if not item:
            raise KeyError(request_id)
        if item["status"] != "PENDING":
            raise ValueError("MCP registry change is already resolved")
        if not item["signature_valid"] or not item["payload_hash_valid"]:
            raise ValueError("MCP registry change evidence failed integrity validation")
        actor = actor_email.strip().lower()
        normalized = decision.upper()
        if normalized not in {"APPROVE", "REJECT"}:
            raise ValueError("Decision must be APPROVE or REJECT")
        if not members.can(item["workspace_id"], actor, "approvals.resolve"):
            raise PermissionError("Actor cannot resolve MCP registry changes")
        if not approval_groups.permits(item["workspace_id"], item["approval_group"], actor):
            raise PermissionError("Actor is not permitted by the MCP approval group")
        if normalized == "APPROVE" and actor == item["requested_by"].lower():
            raise PermissionError("Four-eyes governance forbids self-approval of MCP registry changes")

        now = time.time()
        with store._lock, store._connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO mcp_registry_change_votes(request_id,actor_email,decision,created_at) VALUES(?,?,?,?)",
                (request_id, actor, normalized, now),
            )
            if normalized == "REJECT":
                db.execute("UPDATE mcp_registry_change_requests SET status='REJECTED',updated_at=? WHERE id=?", (now, request_id))
        if normalized == "REJECT":
            return self.get(request_id) or {}

        refreshed = self.get(request_id) or {}
        if refreshed["approval_count"] >= refreshed["required_approvals"]:
            payload = refreshed["payload"]
            applied = mcp_registry.register(item["workspace_id"], **payload)
            with store._lock, store._connect() as db:
                db.execute(
                    "UPDATE mcp_registry_change_requests SET status='APPLIED',updated_at=?,applied_at=? WHERE id=?",
                    (now, now, request_id),
                )
            result = self.get(request_id) or {}
            result["applied_server"] = applied
            return result
        return refreshed


mcp_governance = MCPRegistryGovernance()
