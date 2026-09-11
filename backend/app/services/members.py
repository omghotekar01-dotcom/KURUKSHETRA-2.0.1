from __future__ import annotations
import time
import uuid
from typing import Any, Dict, List, Optional, Set
from .storage import store

VALID_ROLES: Set[str] = {"owner", "admin", "security_analyst", "approver", "developer", "viewer"}
ROLE_CAPABILITIES = {
    "owner": {"workspace.manage", "members.manage", "policies.manage", "approvals.resolve", "incidents.manage", "mcp.manage", "agents.manage", "read"},
    "admin": {"members.manage", "policies.manage", "approvals.resolve", "incidents.manage", "mcp.manage", "agents.manage", "read"},
    "security_analyst": {"policies.manage", "approvals.resolve", "incidents.manage", "mcp.manage", "read"},
    "approver": {"approvals.resolve", "read"},
    "developer": {"agents.manage", "read"},
    "viewer": {"read"},
}


class MemberService:
    def upsert(self, workspace_id: str, email: str, role: str) -> Dict[str, Any]:
        normalized_email = email.strip().lower()
        normalized_role = role.strip().lower()
        if normalized_role not in VALID_ROLES:
            raise ValueError(f"Invalid role: {normalized_role}")
        now = time.time()
        existing = store.workspace_member(workspace_id, normalized_email)
        item = {
            "id": existing["id"] if existing else f"mem_{uuid.uuid4().hex[:10]}",
            "workspace_id": workspace_id,
            "email": normalized_email,
            "role": normalized_role,
            "created_at": existing["created_at"] if existing else now,
            "updated_at": now,
        }
        store.upsert_workspace_member(item)
        return store.workspace_member(workspace_id, normalized_email) or item

    def get(self, workspace_id: str, email: str) -> Optional[Dict[str, Any]]:
        return store.workspace_member(workspace_id, email.strip().lower())

    def list(self, workspace_id: str) -> List[Dict[str, Any]]:
        return store.workspace_members(workspace_id)

    def can(self, workspace_id: str, email: str, capability: str) -> bool:
        member = self.get(workspace_id, email)
        if not member:
            return False
        return capability in ROLE_CAPABILITIES.get(member["role"], set())


members = MemberService()
