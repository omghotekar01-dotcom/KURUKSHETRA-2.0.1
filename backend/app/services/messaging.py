from __future__ import annotations
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional, Tuple
from .storage import store


class MessageSecurity:
    """Replay-resistant HMAC authenticity for the offline MVP."""

    def __init__(self) -> None:
        self.master_key = os.getenv("TRUSTKERNEL_A2A_SIGNING_KEY", "trustkernel-dev-a2a-key").encode("utf-8")
        self.max_clock_skew_seconds = int(os.getenv("TRUSTKERNEL_A2A_MAX_SKEW", "300"))

    def _workspace_key(self, workspace_id: str) -> bytes:
        return hmac.new(self.master_key, workspace_id.encode("utf-8"), hashlib.sha256).digest()

    @staticmethod
    def _canonical(sender: str, recipient: str, nonce: str, timestamp: int, payload: Any) -> bytes:
        payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()
        return f"{sender}|{recipient}|{nonce}|{timestamp}|{payload_hash}".encode("utf-8")

    def sign(self, workspace_id: str, sender: str, recipient: str, nonce: str, timestamp: int, payload: Any) -> str:
        return hmac.new(self._workspace_key(workspace_id), self._canonical(sender, recipient, nonce, timestamp, payload), hashlib.sha256).hexdigest()

    def verify_and_mark(self, *, workspace_id: str, sender: str, recipient: str, nonce: str, timestamp: int, payload: Any, signature: str, now: Optional[int] = None) -> Tuple[bool, str]:
        current = int(time.time() if now is None else now)
        if not nonce:
            return False, "missing_nonce"
        if abs(current - int(timestamp)) > self.max_clock_skew_seconds:
            return False, "stale_timestamp"
        if store.nonce_seen(nonce, current):
            return False, "replay_detected"
        expected = self.sign(workspace_id, sender, recipient, nonce, int(timestamp), payload)
        if not hmac.compare_digest(expected, signature or ""):
            return False, "invalid_signature"
        store.record_nonce(nonce, workspace_id, sender, current, current + self.max_clock_skew_seconds * 2)
        return True, "verified"


message_security = MessageSecurity()
