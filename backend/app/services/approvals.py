from __future__ import annotations
import time
from typing import Any, Dict, List, Optional
from .storage import store


class ApprovalStore:
    def create(self, audit_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        item = {"audit_id": audit_id, "status": "PENDING", "created_at": time.time(), "resolved_at": None, "resolution": None, "payload": payload}
        store.create_approval(item)
        return item

    def resolve(self, audit_id: str, resolution: str, *, actor: str = "demo-operator", role: str = "approver") -> Optional[Dict[str, Any]]:
        item = store.get_approval(audit_id)
        if not item:
            return None
        item["status"] = "RESOLVED"
        item["resolution"] = resolution
        item["resolved_at"] = time.time()
        item["payload"] = {**item["payload"], "resolved_by": actor, "resolver_role": role}
        store.update_approval(item)
        return item

    def get(self, audit_id: str) -> Optional[Dict[str, Any]]:
        return store.get_approval(audit_id)

    def list(self) -> List[Dict[str, Any]]:
        return store.approvals()


approvals = ApprovalStore()
