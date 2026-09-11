from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict, Optional, Tuple

import httpx
import jwt


class OIDCVerifier:
    """OIDC/JWT adapter for enterprise human identity.

    Supports either a static JWKS document (best for offline demos/tests) or a
    remote JWKS URL with a short in-memory cache. The verified principal is
    normalized to the same contract used by TrustKernel's local member
    sessions, so the rest of the authorization layer stays unchanged.
    """

    def __init__(self) -> None:
        self.issuer = os.getenv("TRUSTKERNEL_OIDC_ISSUER", "").rstrip("/")
        self.audience = os.getenv("TRUSTKERNEL_OIDC_AUDIENCE", "")
        self.jwks_url = os.getenv("TRUSTKERNEL_OIDC_JWKS_URL", "")
        self.static_jwks = os.getenv("TRUSTKERNEL_OIDC_JWKS_JSON", "")
        self.workspace_claim = os.getenv("TRUSTKERNEL_OIDC_WORKSPACE_CLAIM", "workspace_id")
        self.email_claim = os.getenv("TRUSTKERNEL_OIDC_EMAIL_CLAIM", "email")
        self.cache_seconds = max(30, int(os.getenv("TRUSTKERNEL_OIDC_JWKS_CACHE_SECONDS", "300")))
        self.allowed_algorithms = [
            item.strip()
            for item in os.getenv("TRUSTKERNEL_OIDC_ALGORITHMS", "RS256,ES256,EdDSA").split(",")
            if item.strip()
        ]
        self._cached_jwks: Optional[Dict[str, Any]] = None
        self._cached_at = 0.0

    @property
    def enabled(self) -> bool:
        return bool(self.issuer and self.audience and (self.static_jwks or self.jwks_url))

    def _jwks(self) -> Dict[str, Any]:
        if self.static_jwks:
            data = json.loads(self.static_jwks)
            if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
                raise ValueError("TRUSTKERNEL_OIDC_JWKS_JSON must contain a JWKS object")
            return data

        now = time.time()
        if self._cached_jwks and now - self._cached_at < self.cache_seconds:
            return self._cached_jwks
        if not self.jwks_url:
            raise ValueError("OIDC JWKS URL is not configured")
        response = httpx.get(self.jwks_url, timeout=5.0, follow_redirects=False)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
            raise ValueError("OIDC JWKS endpoint returned an invalid document")
        self._cached_jwks, self._cached_at = data, now
        return data

    def verify(self, token: str) -> Tuple[Optional[Dict[str, Any]], str]:
        if not self.enabled:
            return None, "oidc_not_configured"
        try:
            header = jwt.get_unverified_header(token)
            alg = str(header.get("alg", ""))
            kid = str(header.get("kid", ""))
            if alg not in self.allowed_algorithms:
                return None, "oidc_algorithm_not_allowed"
            if not kid:
                return None, "oidc_missing_kid"

            jwk = next((item for item in self._jwks()["keys"] if str(item.get("kid", "")) == kid), None)
            if not jwk:
                return None, "oidc_unknown_kid"
            key = jwt.PyJWK.from_dict(jwk).key
            claims = jwt.decode(
                token,
                key=key,
                algorithms=[alg],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "sub"]},
            )

            workspace_id = str(claims.get(self.workspace_claim, "")).strip()
            if not workspace_id:
                return None, "oidc_missing_workspace_claim"
            subject = str(
                claims.get(self.email_claim)
                or claims.get("preferred_username")
                or claims.get("sub")
                or ""
            ).strip().lower()
            if not subject:
                return None, "oidc_missing_subject"
            jti = str(claims.get("jti") or f"oidc_{hashlib.sha256(token.encode('utf-8')).hexdigest()[:24]}")
            return {
                **claims,
                "sub": subject,
                "workspace_id": workspace_id,
                "jti": jti,
                "auth_source": "oidc",
            }, "verified"
        except jwt.ExpiredSignatureError:
            return None, "expired"
        except jwt.InvalidAudienceError:
            return None, "oidc_invalid_audience"
        except jwt.InvalidIssuerError:
            return None, "oidc_invalid_issuer"
        except jwt.InvalidTokenError:
            return None, "oidc_invalid_token"
        except (ValueError, json.JSONDecodeError, httpx.HTTPError):
            return None, "oidc_verification_failed"


oidc = OIDCVerifier()
