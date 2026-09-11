from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException

from .main import _principal, _workspace_match
from .services.mcp_governance import mcp_governance
from .services.oidc import oidc
from .services.otlp import otlp
from .services.workload_identity import workload_identities

router = APIRouter(prefix="/api/v13", tags=["TrustKernel v1.3"])


@router.get("/capabilities")
def capabilities():
    return {
        "version": "1.3.0",
        "identity": ["local_signed_session", "oidc_jwt", "ed25519_workload_identity"],
        "governance": ["policy_four_eyes", "signed_mcp_registry_changes"],
        "observability": ["otlp_json", "otlp_http_transport"],
        "integrations": ["langchain", "langgraph", "autogen", "mcp"],
        "benchmarking": ["security_rate", "utility_rate", "false_positive_rate", "false_negative_rate", "latency"],
    }


@router.get("/identity/oidc/status")
def oidc_status():
    return {
        "enabled": oidc.enabled,
        "issuer": oidc.issuer or None,
        "audience": oidc.audience or None,
        "workspace_claim": oidc.workspace_claim,
        "email_claim": oidc.email_claim,
        "allowed_algorithms": oidc.allowed_algorithms,
        "jwks_mode": "static" if oidc.static_jwks else ("remote" if oidc.jwks_url else "unconfigured"),
    }


@router.get("/workspaces/{workspace_id}/workload-identities/{agent_id}/posture")
def workload_posture(
    workspace_id: str,
    agent_id: str,
    x_trustkernel_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    x_trustkernel_actor: str | None = Header(default=None),
):
    _workspace_match(workspace_id, x_trustkernel_key)
    _principal(workspace_id, authorization, x_trustkernel_actor, "read")
    return workload_identities.posture(workspace_id, agent_id)


@router.post("/workspaces/{workspace_id}/workload-identities/{agent_id}/rotate")
def rotate_workload_identity(
    workspace_id: str,
    agent_id: str,
    payload: dict,
    x_trustkernel_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    x_trustkernel_actor: str | None = Header(default=None),
):
    _workspace_match(workspace_id, x_trustkernel_key)
    _principal(workspace_id, authorization, x_trustkernel_actor, "agents.manage")
    public_key_pem = str(payload.get("public_key_pem", "")).strip()
    if not public_key_pem:
        raise HTTPException(400, "public_key_pem is required")
    try:
        return workload_identities.rotate_public_key(workspace_id, agent_id, public_key_pem)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/workspaces/{workspace_id}/mcp/registry-changes")
def propose_mcp_registry_change(
    workspace_id: str,
    payload: dict,
    x_trustkernel_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    x_trustkernel_actor: str | None = Header(default=None),
):
    _workspace_match(workspace_id, x_trustkernel_key)
    principal = _principal(workspace_id, authorization, x_trustkernel_actor, "mcp.manage")
    name = str(payload.get("name", "")).strip()
    canonical_uri = str(payload.get("canonical_uri", "")).strip()
    if not name or not canonical_uri:
        raise HTTPException(400, "name and canonical_uri are required")
    try:
        return mcp_governance.propose(
            workspace_id,
            requested_by=principal["email"],
            name=name,
            canonical_uri=canonical_uri,
            manifest=str(payload.get("manifest", "")),
            manifest_sha256=payload.get("manifest_sha256"),
            issuer=payload.get("issuer"),
            allowed_scopes=list(payload.get("allowed_scopes", [])),
            status=str(payload.get("status", "ACTIVE")),
            approval_group=str(payload.get("approval_group", "security-approvers")),
        )
    except (PermissionError, ValueError) as exc:
        raise HTTPException(403 if isinstance(exc, PermissionError) else 400, str(exc)) from exc


@router.get("/workspaces/{workspace_id}/mcp/registry-changes")
def list_mcp_registry_changes(
    workspace_id: str,
    x_trustkernel_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    x_trustkernel_actor: str | None = Header(default=None),
):
    _workspace_match(workspace_id, x_trustkernel_key)
    _principal(workspace_id, authorization, x_trustkernel_actor, "read")
    return mcp_governance.list(workspace_id)


@router.post("/workspaces/{workspace_id}/mcp/registry-changes/{request_id}/vote/{decision}")
def vote_mcp_registry_change(
    workspace_id: str,
    request_id: str,
    decision: str,
    x_trustkernel_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    x_trustkernel_actor: str | None = Header(default=None),
):
    _workspace_match(workspace_id, x_trustkernel_key)
    principal = _principal(workspace_id, authorization, x_trustkernel_actor, "approvals.resolve")
    item = mcp_governance.get(request_id)
    if not item or item["workspace_id"] != workspace_id:
        raise HTTPException(404, "MCP registry change not found")
    try:
        return mcp_governance.vote(request_id, principal["email"], decision)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/workspaces/{workspace_id}/telemetry/otlp/send")
def send_otlp(
    workspace_id: str,
    payload: dict | None = None,
    x_trustkernel_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    x_trustkernel_actor: str | None = Header(default=None),
):
    _workspace_match(workspace_id, x_trustkernel_key)
    _principal(workspace_id, authorization, x_trustkernel_actor, "incidents.manage")
    body = payload or {}
    endpoint = str(body.get("endpoint", "")).strip() or None
    limit = max(1, min(int(body.get("limit", 500)), 2000))
    return otlp.send(workspace_id, endpoint=endpoint, limit=limit)
