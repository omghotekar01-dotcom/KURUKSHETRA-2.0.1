from __future__ import annotations
import hashlib
import secrets
import time
import uuid
from typing import Any, Dict, List, Optional
from .storage import store
from .members import members
from .approval_groups import approval_groups


class WorkspaceService:
    @staticmethod
    def _hash_key(raw: str) -> str:
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _issue_key(self, workspace_id: str) -> Dict[str, Any]:
        raw = f"tk_live_{secrets.token_urlsafe(24)}"
        key_id = f"key_{uuid.uuid4().hex[:10]}"
        created_at = time.time()
        store.create_workspace_key({
            "id": key_id,
            "workspace_id": workspace_id,
            "key_hash": self._hash_key(raw),
            "key_prefix": raw[:16],
            "created_at": created_at,
            "revoked_at": None,
        })
        return {"id": key_id, "api_key": raw, "key_prefix": raw[:16], "created_at": created_at}

    def create(self, name: str, owner_email: str = "owner@demo.local") -> Dict[str, Any]:
        workspace_id = f"ws_{uuid.uuid4().hex[:10]}"
        created_at = time.time()
        initial = f"tk_live_{secrets.token_urlsafe(24)}"
        store.create_workspace(workspace_id, name, self._hash_key(initial), created_at)
        key_id = f"key_{uuid.uuid4().hex[:10]}"
        store.create_workspace_key({
            "id": key_id,
            "workspace_id": workspace_id,
            "key_hash": self._hash_key(initial),
            "key_prefix": initial[:16],
            "created_at": created_at,
            "revoked_at": None,
        })
        owner = members.upsert(workspace_id, owner_email, "owner")
        approval_groups.upsert(workspace_id, "security-approvers", roles=["owner", "admin", "security_analyst", "approver"], members_list=[owner["email"]])
        approval_groups.upsert(workspace_id, "finance-approvers", roles=["owner", "admin", "approver"], members_list=[owner["email"]])
        return {
            "id": workspace_id,
            "name": name,
            "created_at": created_at,
            "api_key": initial,
            "key_id": key_id,
            "owner": owner,
            "warning": "This API key is shown once. Store it securely.",
        }

    def authenticate(self, api_key: str) -> Optional[Dict[str, Any]]:
        hashed = self._hash_key(api_key)
        key = store.workspace_key_by_hash(hashed)
        if key:
            if key.get("revoked_at") is not None:
                return None
            return {
                "id": key["workspace_id"],
                "name": key["name"],
                "key_id": key["key_id"],
                "key_prefix": key["key_prefix"],
                "created_at": key["created_at"],
            }
        legacy = store.workspace_by_legacy_key_hash(hashed)
        return legacy

    def rotate_key(self, workspace_id: str) -> Dict[str, Any]:
        workspace = store.workspace(workspace_id)
        if not workspace:
            raise KeyError(workspace_id)
        result = self._issue_key(workspace_id)
        result["workspace_id"] = workspace_id
        result["warning"] = "New key shown once. Existing keys remain active until revoked."
        return result

    def revoke_key(self, workspace_id: str, key_id: str) -> bool:
        return store.revoke_workspace_key(workspace_id, key_id, time.time())

    def keys(self, workspace_id: str) -> List[Dict[str, Any]]:
        return store.workspace_keys(workspace_id)

    def list(self) -> List[Dict[str, Any]]:
        return store.workspaces()


workspaces = WorkspaceService()
