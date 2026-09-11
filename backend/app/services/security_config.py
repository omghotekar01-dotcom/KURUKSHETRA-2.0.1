from __future__ import annotations
import os
from typing import Dict, Any

DEFAULT_SECRETS = {
    "TRUSTKERNEL_SESSION_SIGNING_KEY": "trustkernel-dev-session-key",
    "TRUSTKERNEL_A2A_SIGNING_KEY": "trustkernel-dev-a2a-key",
    "TRUSTKERNEL_POLICY_SIGNING_KEY": "trustkernel-dev-policy-signing-key",
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
    if os.getenv("TRUSTKERNEL_CORS_ORIGINS", "*") == "*":
        (errors if production else warnings).append("CORS allows all origins")
    return {
        "environment": env,
        "production_ready": not errors,
        "errors": errors,
        "warnings": warnings,
        "weak_secret_variables": weak,
    }
