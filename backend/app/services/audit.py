from __future__ import annotations
import hashlib
import json
import time
import uuid
from typing import Any, Dict, List
from .storage import store


class AuditLedger:
    @staticmethod
    def _hash_body(body: Dict[str, Any]) -> str:
        canonical = {key: value for key, value in body.items() if key != "hash"}
        raw = json.dumps(canonical, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def append(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        entries = store.audit_entries()
        prev_hash = entries[-1]["hash"] if entries else "GENESIS"
        body = {
            "id": f"AUD-{uuid.uuid4().hex[:10].upper()}",
            "timestamp": time.time(),
            "prev_hash": prev_hash,
            "payload": payload,
        }
        body["hash"] = self._hash_body(body)
        store.append_audit(body)
        return body

    def list(self, workspace_id: str | None = None) -> List[Dict[str, Any]]:
        entries = list(reversed(store.audit_entries()))
        if workspace_id is None:
            return [entry for entry in entries if entry.get("payload", {}).get("workspace_id") is None]
        return [entry for entry in entries if entry.get("payload", {}).get("workspace_id") == workspace_id]

    def verify(self) -> Dict[str, Any]:
        entries = store.audit_entries()
        previous = "GENESIS"
        for index, entry in enumerate(entries):
            if entry.get("prev_hash") != previous:
                return {"valid": False, "entries": len(entries), "broken_at": index, "reason": "previous hash mismatch"}
            expected = self._hash_body(entry)
            if entry.get("hash") != expected:
                return {"valid": False, "entries": len(entries), "broken_at": index, "reason": "entry hash mismatch"}
            previous = entry["hash"]
        return {"valid": True, "entries": len(entries), "head_hash": previous}


ledger = AuditLedger()
