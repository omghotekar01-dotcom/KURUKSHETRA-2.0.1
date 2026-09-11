from __future__ import annotations
import os
from typing import Dict, Any

DEFAULT_SECRETS = {
    "TRUSTKERNEL_SESSION_SIGNING_KEY": "trustkernel-dev-session-key",
    "TRUSTKERNEL_A2A_SIGNING_KEY": "trustkernel-dev-a2a-key",
    "TRUSTKERNEL_POLICY_SIGNING_KEY": "trustkernel-dev-policy-signing-key",
    "TRUSTKERNEL_EVIDENCE_SIGNING_KEY": "trustkernel-dev-policy-signing-key",
}


def security_posture() -> Dict[str, Any]:
    env = os.getenv("TRUSTKERNEL_ENV", "development").lower()
    weak = []
    for key, default in DEFAULT_SECRETS.items():
        if os.getenv(key, default) == default:
            weak.append(key)
    production = env == "production"
    errors = []
    warnings = []

    oidc_configured = bool(
        os.getenv("TRUSTKERNEL_OIDC_ISSUER")
        and os.getenv("TRUSTKERNEL_OIDC_AUDIENCE")
    )
    oidc_https = os.getenv("TRUSTKERNEL_OIDC_REQUIRE_HTTPS", "1") == "1"
    four_eyes = os.getenv("TRUSTKERNEL_POLICY_FOUR_EYES", "1") == "1"
    evidence_key_explicit = bool(os.getenv("TRUSTKERNEL_EVIDENCE_SIGNING_KEY"))

    if production and weak:
        errors.append("Production profile cannot use development signing keys")
    elif weak:
        warnings.append("Development signing keys are active; rotate before production")
    if os.getenv("TRUSTKERNEL_REQUIRE_API_KEY", "0") != "1":
        (errors if production else warnings).append("Gateway API-key enforcement is not mandatory")
    if os.getenv("TRUSTKERNEL_ALLOW_LEGACY_ACTOR_HEADER", "1") == "1":
        (errors if production else warnings).append("Legacy actor-header compatibility is enabled")
    if os.getenv("TRUSTKERNEL_REQUIRE_POLICY_APPROVAL", "0") != "1":
        (errors if production else warnings).append("Direct policy activation remains enabled")
    if not four_eyes:
        (errors if production else warnings).append("Four-eyes policy governance is disabled")
    if os.getenv("TRUSTKERNEL_CORS_ORIGINS", "*") == "*":
        (errors if production else warnings).append("CORS allows all origins")
    if not oidc_configured:
        warnings.append("External OIDC identity provider is not configured; local signed sessions remain active")
    if production and oidc_configured and not oidc_https:
        errors.append("Production OIDC configuration must enforce HTTPS discovery/JWKS endpoints")
    if production and not evidence_key_explicit:
        errors.append("Production governance evidence requires a dedicated signing key")

    return {
        "environment": env,
        "production_ready": not errors,
        "errors": errors,
        "warnings": warnings,
        "weak_secret_variables": weak,
        "controls": {
            "api_key_required": os.getenv("TRUSTKERNEL_REQUIRE_API_KEY", "0") == "1",
            "legacy_actor_header_disabled": os.getenv("TRUSTKERNEL_ALLOW_LEGACY_ACTOR_HEADER", "1") != "1",
            "policy_change_approval_required": os.getenv("TRUSTKERNEL_REQUIRE_POLICY_APPROVAL", "0") == "1",
            "policy_four_eyes": four_eyes,
            "external_oidc_configured": oidc_configured,
            "oidc_https_required": oidc_https,
            "governance_evidence_signing_configured": evidence_key_explicit,
        },
    }
