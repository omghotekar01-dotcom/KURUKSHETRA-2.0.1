from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import httpx
import jwt


class OIDCVerifier:
    """OIDC/JWT adapter for enterprise human identity.

    v1.4 supports standards-based provider discovery, exact issuer matching,
    HTTPS endpoint validation, explicit audience validation, cached JWKS, and
    configurable role-claim mapping. Static JWKS remains available for offline
    demos and deterministic tests.
    """

    def __init__(self) -> None:
        self.issuer = os.getenv("TRUSTKERNEL_OIDC_ISSUER", "").rstrip("/")
        self.audience = os.getenv("TRUSTKERNEL_OIDC_AUDIENCE", "")
        self.discovery_url = os.getenv("TRUSTKERNEL_OIDC_DISCOVERY_URL", "")
        self.jwks_url = os.getenv("TRUSTKERNEL_OIDC_JWKS_URL", "")
        self.static_jwks = os.getenv("TRUSTKERNEL_OIDC_JWKS_JSON", "")
        self.workspace_claim = os.getenv("TRUSTKERNEL_OIDC_WORKSPACE_CLAIM", "workspace_id")
        self.email_claim = os.getenv("TRUSTKERNEL_OIDC_EMAIL_CLAIM", "email")
        self.role_claim = os.getenv("TRUSTKERNEL_OIDC_ROLE_CLAIM", "roles")
        self.default_role = os.getenv("TRUSTKERNEL_OIDC_DEFAULT_ROLE", "viewer").strip().lower()
        self.role_map = self._load_role_map(os.getenv("TRUSTKERNEL_OIDC_ROLE_MAP_JSON", "{}"))
        self.cache_seconds = max(30, int(os.getenv("TRUSTKERNEL_OIDC_JWKS_CACHE_SECONDS", "300")))
        self.clock_skew_seconds = max(0, int(os.getenv("TRUSTKERNEL_OIDC_CLOCK_SKEW_SECONDS", "30")))
        self.require_https = os.getenv("TRUSTKERNEL_OIDC_REQUIRE_HTTPS", "1") == "1"
        self.allowed_algorithms = [
            item.strip()
            for item in os.getenv("TRUSTKERNEL_OIDC_ALGORITHMS", "RS256,ES256,EdDSA").split(",")
            if item.strip()
        ]
        self._cached_jwks: Optional[Dict[str, Any]] = None
        self._cached_jwks_at = 0.0
        self._cached_metadata: Optional[Dict[str, Any]] = None
        self._cached_metadata_at = 0.0

    @staticmethod
    def _load_role_map(raw: str) -> Dict[str, str]:
        try:
            data = json.loads(raw or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError("TRUSTKERNEL_OIDC_ROLE_MAP_JSON must be valid JSON") from exc
        if not isinstance(data, dict):
            raise ValueError("TRUSTKERNEL_OIDC_ROLE_MAP_JSON must be a JSON object")
        return {str(k).strip(): str(v).strip().lower() for k, v in data.items() if str(k).strip() and str(v).strip()}

    @property
    def enabled(self) -> bool:
        return bool(self.issuer and self.audience and (self.static_jwks or self.jwks_url or self.discovery_url or self.issuer))

    def _assert_secure_url(self, value: str, label: str) -> None:
        parsed = urlparse(value)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"{label} must be an absolute URL")
        if self.require_https and parsed.scheme.lower() != "https":
            raise ValueError(f"{label} must use HTTPS")

    def _metadata_endpoint(self) -> str:
        if self.discovery_url:
            return self.discovery_url
        return f"{self.issuer}/.well-known/openid-configuration"

    def metadata(self) -> Dict[str, Any]:
        now = time.time()
        if self._cached_metadata and now - self._cached_metadata_at < self.cache_seconds:
            return self._cached_metadata
        endpoint = self._metadata_endpoint()
        self._assert_secure_url(endpoint, "OIDC discovery URL")
        response = httpx.get(endpoint, timeout=5.0, follow_redirects=False)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("OIDC discovery endpoint returned an invalid document")
        discovered_issuer = str(data.get("issuer", "")).rstrip("/")
        if discovered_issuer != self.issuer:
            raise ValueError("OIDC discovery issuer does not match TRUSTKERNEL_OIDC_ISSUER")
        jwks_uri = str(data.get("jwks_uri", ""))
        if not jwks_uri:
            raise ValueError("OIDC discovery document is missing jwks_uri")
        self._assert_secure_url(jwks_uri, "OIDC jwks_uri")
        supported = data.get("id_token_signing_alg_values_supported")
        if isinstance(supported, list) and not set(self.allowed_algorithms).intersection({str(x) for x in supported}):
            raise ValueError("OIDC provider exposes no signing algorithm allowed by TrustKernel")
        self._cached_metadata, self._cached_metadata_at = data, now
        return data

    def _effective_jwks_url(self) -> str:
        if self.jwks_url:
            self._assert_secure_url(self.jwks_url, "OIDC JWKS URL")
            return self.jwks_url
        return str(self.metadata()["jwks_uri"])

    def _jwks(self, *, force_refresh: bool = False) -> Dict[str, Any]:
        if self.static_jwks:
            data = json.loads(self.static_jwks)
            if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
                raise ValueError("TRUSTKERNEL_OIDC_JWKS_JSON must contain a JWKS object")
            return data

        now = time.time()
        if not force_refresh and self._cached_jwks and now - self._cached_jwks_at < self.cache_seconds:
            return self._cached_jwks
        endpoint = self._effective_jwks_url()
        response = httpx.get(endpoint, timeout=5.0, follow_redirects=False)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
            raise ValueError("OIDC JWKS endpoint returned an invalid document")
        self._cached_jwks, self._cached_jwks_at = data, now
        return data

    def _mapped_role(self, claims: Dict[str, Any]) -> Tuple[str, list[str]]:
        raw = claims.get(self.role_claim, [])
        external_roles = [str(raw)] if isinstance(raw, str) else [str(x) for x in raw] if isinstance(raw, list) else []
        for external in external_roles:
            mapped = self.role_map.get(external)
            if mapped:
                return mapped, external_roles
        return self.default_role, external_roles

    def verify(self, token: str) -> Tuple[Optional[Dict[str, Any]], str]:
        if not self.enabled:
            return None, "oidc_not_configured"
        try:
            self._assert_secure_url(self.issuer, "OIDC issuer")
            header = jwt.get_unverified_header(token)
            alg = str(header.get("alg", ""))
            kid = str(header.get("kid", ""))
            if alg not in self.allowed_algorithms:
                return None, "oidc_algorithm_not_allowed"
            if not kid:
                return None, "oidc_missing_kid"

            keys = self._jwks()["keys"]
            jwk = next((item for item in keys if str(item.get("kid", "")) == kid), None)
            if not jwk and not self.static_jwks:
                keys = self._jwks(force_refresh=True)["keys"]
                jwk = next((item for item in keys if str(item.get("kid", "")) == kid), None)
            if not jwk:
                return None, "oidc_unknown_kid"
            if jwk.get("use") not in {None, "sig"}:
                return None, "oidc_key_not_for_signing"
            if jwk.get("alg") and str(jwk["alg"]) != alg:
                return None, "oidc_jwk_algorithm_mismatch"

            key = jwt.PyJWK.from_dict(jwk).key
            claims = jwt.decode(
                token,
                key=key,
                algorithms=[alg],
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.clock_skew_seconds,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
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
            mapped_role, external_roles = self._mapped_role(claims)
            jti = str(claims.get("jti") or f"oidc_{hashlib.sha256(token.encode('utf-8')).hexdigest()[:24]}")
            return {
                **claims,
                "sub": subject,
                "workspace_id": workspace_id,
                "jti": jti,
                "auth_source": "oidc",
                "mapped_role": mapped_role,
                "external_roles": external_roles,
            }, "verified"
        except jwt.ExpiredSignatureError:
            return None, "expired"
        except jwt.ImmatureSignatureError:
            return None, "oidc_token_not_yet_valid"
        except jwt.InvalidAudienceError:
            return None, "oidc_invalid_audience"
        except jwt.InvalidIssuerError:
            return None, "oidc_invalid_issuer"
        except jwt.InvalidTokenError:
            return None, "oidc_invalid_token"
        except (ValueError, json.JSONDecodeError, httpx.HTTPError):
            return None, "oidc_verification_failed"


oidc = OIDCVerifier()
