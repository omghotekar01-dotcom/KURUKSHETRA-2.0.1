from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException

from .main import _principal, _workspace_match
from .services.governance_evidence import governance_evidence
from .services.mcp_governance import mcp_governance
from .services.oidc import oidc
from .services.policy_changes import policy_changes

router = APIRouter(prefix="/api/v14", tags=["TrustKernel v1.4"])


@router.get("/capabilities")
def capabilities():
    return {
        "version": "1.4.2",
        "identity": {
            "oidc_discovery": True,
            "exact_issuer_validation": True,
            "audience_validation": True,
            "jwks_rotation_refresh": True,
            "configurable_role_claim_mapping": True,
            "workload_attestation_metadata": True,
            "external_signer_adapter": True,
            "spiffe_style_identity_metadata": True,
            "kms_hsm_private_key_custody": True,
        },
        "governance": {
            "four_eyes_policy_changes": True,
            "four_eyes_mcp_registry_changes": True,
            "portable_signed_evidence": True,
        },
        "deployment": {
            "offline_sqlite_mode": True,
            "postgresql_mode": True,
            "schema_migrations": True,
            "container_non_root": True,
        },
    }


@router.get("/identity/oidc/status")
def oidc_status():
    return {
        "enabled": oidc.enabled,
        "issuer": oidc.issuer or None,
        "audience": oidc.audience or None,
        "discovery_url": oidc._metadata_endpoint() if oidc.issuer else None,
        "workspace_claim": oidc.workspace_claim,
        "email_claim": oidc.email_claim,
        "role_claim": oidc.role_claim,
        "default_role": oidc.default_role,
        "role_map": oidc.role_map,
        "allowed_algorithms": oidc.allowed_algorithms,
        "require_https": oidc.require_https,
        "clock_skew_seconds": oidc.clock_skew_seconds,
        "jwks_mode": "static" if oidc.static_jwks else ("explicit_remote" if oidc.jwks_url else "discovery"),
    }


@router.get("/identity/oidc/discovery")
def oidc_discovery():
    if not oidc.enabled or oidc.static_jwks:
        raise HTTPException(409, "OIDC discovery is not active for the current configuration")
    try:
        metadata = oidc.metadata()
    except Exception as exc:
        raise HTTPException(502, f"OIDC discovery validation failed: {exc}") from exc
    return {
        "issuer": metadata.get("issuer"),
        "jwks_uri": metadata.get("jwks_uri"),
        "authorization_endpoint": metadata.get("authorization_endpoint"),
        "token_endpoint": metadata.get("token_endpoint"),
        "id_token_signing_alg_values_supported": metadata.get("id_token_signing_alg_values_supported", []),
        "validated": True,
    }


def _evidence_access(workspace_id: str, key: str | None, authorization: str | None, actor: str | None) -> None:
    _workspace_match(workspace_id, key)
    _principal(workspace_id, authorization, actor, "read")


@router.get("/workspaces/{workspace_id}/policy-changes/{request_id}/evidence")
def policy_change_evidence(
    workspace_id: str,
    request_id: str,
    x_trustkernel_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    x_trustkernel_actor: str | None = Header(default=None),
):
    _evidence_access(workspace_id, x_trustkernel_key, authorization, x_trustkernel_actor)
    item = policy_changes.get(request_id)
    if not item or item["workspace_id"] != workspace_id:
        raise HTTPException(404, "Policy change not found")
    return governance_evidence.policy_change(request_id)


@router.get("/workspaces/{workspace_id}/mcp/registry-changes/{request_id}/evidence")
def mcp_change_evidence(
    workspace_id: str,
    request_id: str,
    x_trustkernel_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    x_trustkernel_actor: str | None = Header(default=None),
):
    _evidence_access(workspace_id, x_trustkernel_key, authorization, x_trustkernel_actor)
    item = mcp_governance.get(request_id)
    if not item or item["workspace_id"] != workspace_id:
        raise HTTPException(404, "MCP registry change not found")
    return governance_evidence.mcp_change(request_id)


@router.post("/evidence/verify")
def verify_evidence(payload: dict):
    return governance_evidence.verify(payload)
