from __future__ import annotations
import time
import uuid
from typing import Any, Dict, List

from .approval_groups import approval_groups
from .members import members
from .policies import active_policy_bundle, activate_policy_bundle
from .storage import store


def _flatten(value: Any, prefix: str = "") -> Dict[str, Any]:
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for key, child in sorted(value.items()):
            path = f"{prefix}.{key}" if prefix else str(key)
            out.update(_flatten(child, path))
        return out
    return {prefix: value}


def policy_diff(before: Dict[str, Any], after: Dict[str, Any]) -> List[Dict[str, Any]]:
    left, right = _flatten(before), _flatten(after)
    result: List[Dict[str, Any]] = []
    for path in sorted(set(left) | set(right)):
        if left.get(path) != right.get(path):
            result.append({"path": path, "before": left.get(path), "after": right.get(path)})
    return result


class PolicyChangeService:
    def propose(self, workspace_id: str, profile: str, bundle_id: str, requested_by: str, approval_group: str = "security-approvers") -> Dict[str, Any]:
        bundle = store.policy_bundle(bundle_id)
        if not bundle or bundle["profile"] != profile:
            raise KeyError(bundle_id)
        active = active_policy_bundle(workspace_id, profile)
        before = active["policy"] if active else {}
        diff = policy_diff(before, bundle["policy"])
        now = time.time()
        item = {
            "id": f"pcr_{uuid.uuid4().hex[:12]}", "workspace_id": workspace_id,
            "profile": profile, "bundle_id": bundle_id, "requested_by": requested_by,
            "approval_group": approval_group, "status": "PENDING", "diff": diff,
            "created_at": now, "updated_at": now, "activated_at": None,
        }
        store.create_policy_change(item)
        return self.get(item["id"]) or item

    def get(self, request_id: str) -> Dict[str, Any] | None:
        item = store.policy_change(request_id)
        if not item:
            return None
        item["votes"] = store.policy_change_votes(request_id)
        group = approval_groups.get(item["workspace_id"], item["approval_group"])
        item["required_approvals"] = int(group.get("min_approvals", 1)) if group else 1
        item["approval_count"] = sum(1 for v in item["votes"] if v["decision"] == "APPROVE")
        return item

    def list(self, workspace_id: str) -> List[Dict[str, Any]]:
        return [self.get(i["id"]) for i in store.policy_changes(workspace_id)]

    def vote(self, request_id: str, actor_email: str, decision: str) -> Dict[str, Any]:
        item = self.get(request_id)
        if not item:
            raise KeyError(request_id)
        if item["status"] != "PENDING":
            raise ValueError("Policy change request is already resolved")
        actor = actor_email.lower()
        if not members.can(item["workspace_id"], actor, "approvals.resolve"):
            raise PermissionError("Actor cannot resolve policy changes")
        if not approval_groups.permits(item["workspace_id"], item["approval_group"], actor):
            raise PermissionError("Actor is not permitted by the policy approval group")
        normalized = decision.upper()
        if normalized not in {"APPROVE", "REJECT"}:
            raise ValueError("Decision must be APPROVE or REJECT")
        now = time.time()
        store.upsert_policy_change_vote(request_id, actor, normalized, now)
        if normalized == "REJECT":
            store.update_policy_change(request_id, status="REJECTED", updated_at=now)
            return self.get(request_id) or {}
        refreshed = self.get(request_id) or {}
        if refreshed.get("approval_count", 0) >= refreshed.get("required_approvals", 1):
            activate_policy_bundle(item["workspace_id"], item["profile"], item["bundle_id"], activated_by=f"approved:{actor}")
            store.update_policy_change(request_id, status="ACTIVATED", updated_at=now, activated_at=now)
        return self.get(request_id) or {}


policy_changes = PolicyChangeService()
