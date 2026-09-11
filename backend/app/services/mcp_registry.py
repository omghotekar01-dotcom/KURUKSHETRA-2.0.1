from __future__ import annotations
import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from ..models import Action
from .storage import store


class MCPRegistry:
    def register(self, workspace_id: str, *, name: str, canonical_uri: str, manifest: str | None = None, manifest_sha256: str | None = None, issuer: str | None = None, allowed_scopes: List[str] | None = None, status: str = "ACTIVE") -> Dict[str, Any]:
        if not manifest_sha256:
            manifest_sha256 = hashlib.sha256((manifest or "").encode("utf-8")).hexdigest()
        existing = store.mcp_server(workspace_id, canonical_uri=canonical_uri)
        now = time.time()
        item = {
            "id": existing["id"] if existing else f"mcp_{uuid.uuid4().hex[:10]}",
            "workspace_id": workspace_id,
            "name": name,
            "canonical_uri": canonical_uri.rstrip("/"),
            "issuer": issuer,
            "manifest_sha256": manifest_sha256,
            "allowed_scopes": sorted(set(allowed_scopes or [])),
            "status": status.upper(),
            "created_at": existing["created_at"] if existing else now,
            "updated_at": now,
        }
        store.upsert_mcp_server(item)
        return store.mcp_server(workspace_id, server_id=item["id"]) or item

    def list(self, workspace_id: str) -> List[Dict[str, Any]]:
        return store.mcp_servers(workspace_id)

    def get(self, workspace_id: str, server_id: str | None = None, canonical_uri: str | None = None) -> Optional[Dict[str, Any]]:
        return store.mcp_server(workspace_id, server_id=server_id, canonical_uri=canonical_uri)

    def enrich(self, action: Action, workspace_id: Optional[str]) -> Tuple[Action, List[str]]:
        if not workspace_id or not (action.tool == "mcp_tool" or str(action.metadata.get("source_kind", "")).lower() == "mcp"):
            return action, []
        metadata = dict(action.metadata)
        server_id = metadata.get("mcp_server_id")
        canonical_uri = metadata.get("mcp_resource") or action.destination
        server = self.get(workspace_id, server_id=server_id, canonical_uri=canonical_uri if not server_id else None)
        reasons: List[str] = []
        if not server or server.get("status") != "ACTIVE":
            metadata.update({"provenance_verified": False, "manifest_hash_match": False, "mcp_registered": False})
            reasons.append("MCP server is not registered as an active trusted resource in this workspace.")
            return action.model_copy(update={"metadata": metadata}), reasons

        metadata["mcp_registered"] = True
        metadata["mcp_server_id"] = server["id"]
        metadata["provenance_verified"] = True
        supplied_manifest = metadata.get("manifest_sha256")
        if supplied_manifest:
            metadata["manifest_hash_match"] = supplied_manifest == server["manifest_sha256"]
        else:
            metadata.setdefault("manifest_hash_match", True)

        token_resource = str(metadata.get("token_resource", "")).rstrip("/")
        metadata["token_audience_valid"] = bool(token_resource and token_resource == server["canonical_uri"])
        requested_scopes = set(metadata.get("requested_scopes", []))
        allowed = set(server.get("allowed_scopes", []))
        metadata["scope_valid"] = not requested_scopes or requested_scopes.issubset(allowed)
        metadata["registered_manifest_sha256"] = server["manifest_sha256"]
        metadata["registered_issuer"] = server.get("issuer")
        return action.model_copy(update={"metadata": metadata}), reasons


mcp_registry = MCPRegistry()
