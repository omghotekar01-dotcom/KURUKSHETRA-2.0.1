from __future__ import annotations
import base64
import hashlib
import json
import time
import uuid
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .storage import store


def _canonical(sender: str, recipient: str, nonce: str, timestamp: int, payload: Any) -> bytes:
    payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()
    return f"{sender}|{recipient}|{nonce}|{timestamp}|{payload_hash}".encode("utf-8")


class WorkloadIdentityService:
    algorithm = "Ed25519"

    def register_public_key(self, workspace_id: str, agent_id: str, public_key_pem: str) -> Dict[str, Any]:
        key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("Only Ed25519 workload identity keys are supported in v1.2")
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        fingerprint = hashlib.sha256(raw).hexdigest()
        existing = next((k for k in store.workload_keys(workspace_id, agent_id) if k["fingerprint"] == fingerprint), None)
        if existing:
            return existing
        item = {
            "id": f"wid_{uuid.uuid4().hex[:12]}", "workspace_id": workspace_id, "agent_id": agent_id,
            "algorithm": self.algorithm, "public_key_pem": public_key_pem, "fingerprint": fingerprint,
            "status": "ACTIVE", "created_at": time.time(), "revoked_at": None,
        }
        store.create_workload_key(item)
        return item

    def generate_demo_keypair(self, workspace_id: str, agent_id: str) -> Dict[str, Any]:
        private = Ed25519PrivateKey.generate()
        private_pem = private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode("utf-8")
        public_pem = private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
        registered = self.register_public_key(workspace_id, agent_id, public_pem)
        return {**registered, "private_key_pem": private_pem, "warning": "Demo helper returns the private key once; production keys should remain in workload/KMS custody."}

    def sign(self, private_key_pem: str, sender: str, recipient: str, nonce: str, timestamp: int, payload: Any) -> str:
        key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Private key is not Ed25519")
        return base64.urlsafe_b64encode(key.sign(_canonical(sender, recipient, nonce, timestamp, payload))).decode("ascii").rstrip("=")

    def verify_and_mark(self, *, workspace_id: str, key_id: str, sender: str, recipient: str, nonce: str, timestamp: int, payload: Any, signature: str, max_skew: int = 300, now: Optional[int] = None) -> Tuple[bool, str]:
        current = int(time.time() if now is None else now)
        if not nonce:
            return False, "missing_nonce"
        if abs(current - int(timestamp)) > max_skew:
            return False, "stale_timestamp"
        if store.nonce_seen(nonce, current):
            return False, "replay_detected"
        item = store.workload_key(workspace_id, key_id)
        if not item or item.get("status") != "ACTIVE":
            return False, "unknown_or_revoked_workload_key"
        if item.get("agent_id") != sender:
            return False, "sender_key_mismatch"
        try:
            key = serialization.load_pem_public_key(item["public_key_pem"].encode("utf-8"))
            if not isinstance(key, Ed25519PublicKey):
                return False, "unsupported_algorithm"
            padded = signature + "=" * (-len(signature) % 4)
            key.verify(base64.urlsafe_b64decode(padded), _canonical(sender, recipient, nonce, int(timestamp), payload))
        except (InvalidSignature, ValueError, TypeError):
            return False, "invalid_signature"
        store.record_nonce(nonce, workspace_id, sender, current, current + max_skew * 2)
        return True, "verified"

    def list(self, workspace_id: str, agent_id: Optional[str] = None):
        return store.workload_keys(workspace_id, agent_id)

    def revoke(self, workspace_id: str, key_id: str) -> bool:
        return store.revoke_workload_key(workspace_id, key_id, time.time())


workload_identities = WorkloadIdentityService()
