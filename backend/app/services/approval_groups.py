from __future__ import annotations
import time
import uuid
from typing import Any, Dict, List, Optional
from .storage import store
from .members import members


class ApprovalGroupService:
    def upsert(self, workspace_id: str, name: str, *, roles: List[str] | None = None, members_list: List[str] | None = None, min_approvals: int = 1) -> Dict[str, Any]:
        existing = store.approval_group(workspace_id, name)
        item = {
            "id": existing["id"] if existing else f"grp_{uuid.uuid4().hex[:10]}",
            "workspace_id": workspace_id,
            "name": name,
            "roles": sorted({r.lower() for r in (roles or ["owner", "admin", "approver"])}),
            "members": sorted({m.lower() for m in (members_list or [])}),
            "min_approvals": max(1, int(min_approvals)),
            "created_at": existing["created_at"] if existing else time.time(),
        }
        store.upsert_approval_group(item)
        return store.approval_group(workspace_id, name) or item

    def list(self, workspace_id: str) -> List[Dict[str, Any]]:
        return store.approval_groups(workspace_id)

    def get(self, workspace_id: str, name: str) -> Optional[Dict[str, Any]]:
        return store.approval_group(workspace_id, name)

    def permits(self, workspace_id: str, group_name: str, actor_email: str) -> bool:
        group = self.get(workspace_id, group_name)
        if not group:
            return members.can(workspace_id, actor_email, "approvals.resolve")
        actor = actor_email.lower()
        if actor in set(group.get("members", [])):
            return True
        member = members.get(workspace_id, actor)
        return bool(member and member["role"] in set(group.get("roles", [])) and members.can(workspace_id, actor, "approvals.resolve"))


approval_groups = ApprovalGroupService()
