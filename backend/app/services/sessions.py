from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, Optional, Tuple

from .members import members
from .storage import store


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class SessionService:
    """Small HMAC-backed member sessions for the offline-first MVP.

    The token format is deliberately simple and dependency-free. Production
    deployments can replace this adapter with OIDC/JWT while preserving the
    principal contract returned by verify().
    """

    def __init__(self) -> None:
        self.key = os.getenv("TRUSTKERNEL_SESSION_SIGNING_KEY", "trustkernel-dev-session-key").encode("utf-8")
        self.ttl_seconds = int(os.getenv("TRUSTKERNEL_SESSION_TTL_SECONDS", "3600"))

    def issue(self, workspace_id: str, email: str, ttl_seconds: Optional[int] = None) -> Dict[str, Any]:
        member = members.get(workspace_id, email)
        if not member:
            raise KeyError(email)
        now = int(time.time())
        exp = now + max(60, min(int(ttl_seconds or self.ttl_seconds), 86400))
        claims = {
            "sub": member["email"],
            "workspace_id": workspace_id,
            "role": member["role"],
            "iat": now,
            "exp": exp,
            "jti": f"ses_{secrets.token_urlsafe(12)}",
        }
        body = _b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        sig = _b64(hmac.new(self.key, body.encode("ascii"), hashlib.sha256).digest())
        token = f"tk_session.{body}.{sig}"
        store.create_member_session({
            "jti": claims["jti"], "workspace_id": workspace_id, "email": member["email"],
            "role": member["role"], "issued_at": now, "expires_at": exp, "revoked_at": None,
        })
        return {"token": token, "token_type": "Bearer", "expires_at": exp, "principal": claims}

    def verify(self, token: str) -> Tuple[Optional[Dict[str, Any]], str]:
        try:
            prefix, body, sig = token.split(".", 2)
            if prefix != "tk_session":
                return None, "invalid_prefix"
            expected = _b64(hmac.new(self.key, body.encode("ascii"), hashlib.sha256).digest())
            if not hmac.compare_digest(expected, sig):
                return None, "invalid_signature"
            claims = json.loads(_unb64(body).decode("utf-8"))
            now = int(time.time())
            if int(claims.get("exp", 0)) <= now:
                return None, "expired"
            row = store.member_session(str(claims.get("jti", "")))
            if not row or row.get("revoked_at") is not None:
                return None, "revoked_or_unknown"
            member = members.get(claims["workspace_id"], claims["sub"])
            if not member:
                return None, "member_removed"
            claims["role"] = member["role"]
            return claims, "verified"
        except Exception:
            return None, "malformed"

    def revoke(self, jti: str) -> bool:
        return store.revoke_member_session(jti, time.time())


sessions = SessionService()
