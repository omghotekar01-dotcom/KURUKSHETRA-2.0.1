from __future__ import annotations

from pathlib import Path
import os
import secrets
import time

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .benchmarks.adapter import benchmark_adapter
from .engines.kernel import evaluate_plan
from .models import AgentIdentity, GatewayRequest, PlanRequest
from .scenarios import SCENARIOS
from .services.agents import agents
from .services.approval_groups import approval_groups
from .services.approvals import approvals
from .services.audit import ledger
from .services.incidents import incidents
from .services.mcp_registry import mcp_registry
from .services.members import VALID_ROLES, members
from .services.messaging import message_security
from .services.otlp import otlp
from .services.policies import (
    activate_policy_bundle,
    active_policy_bundle,
    list_policies,
    list_policy_bundles,
    load_policy,
    policy_metadata,
    publish_policy_bundle,
    publish_policy_document,
    validate_policy,
)
from .services.policy_changes import policy_changes
from .services.quotas import quotas
from .services.security_config import security_posture
from .services.sessions import sessions
from .services.storage import store
from .services.telemetry import telemetry
from .services.workload_identity import workload_identities
from .services.workspaces import workspaces

VERSION = "1.2.0"
app = FastAPI(
    title="TrustKernel",
    version=VERSION,
    description="Runtime authorization and security control plane for autonomous AI agents",
)

_cors = [item.strip() for item in os.getenv("TRUSTKERNEL_CORS_ORIGINS", "*").split(",") if item.strip()] or ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors,
    allow_credentials="*" not in _cors,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-TrustKernel-Key", "X-TrustKernel-Actor", "X-TrustKernel-Role"],
)

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.middleware("http")
async def harden_http(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'"
    return response


def _workspace(key: str | None, required: bool | None = None) -> dict | None:
    must_auth = os.getenv("TRUSTKERNEL_REQUIRE_API_KEY", "0") == "1" if required is None else required
    if not key:
        if must_auth:
            raise HTTPException(401, "X-TrustKernel-Key is required")
        return None
    item = workspaces.authenticate(key)
    if not item:
        raise HTTPException(401, "Invalid or revoked TrustKernel API key")
    return item


def _workspace_match(workspace_id: str, key: str | None) -> dict:
    item = _workspace(key, True)
    if item["id"] != workspace_id:
        raise HTTPException(403, "API key does not belong to this workspace")
    return item


def _principal(workspace_id: str, authorization: str | None, actor_header: str | None, capability: str | None = None) -> dict:
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(401, "Authorization must be Bearer <session-token>")
        claims, reason = sessions.verify(token)
        if not claims:
            raise HTTPException(401, f"Invalid member session: {reason}")
        if claims["workspace_id"] != workspace_id:
            raise HTTPException(403, "Session belongs to another workspace")
        member = members.get(workspace_id, claims["sub"])
        if not member:
            raise HTTPException(403, "Session member no longer exists")
        if capability and not members.can(workspace_id, member["email"], capability):
            raise HTTPException(403, f"Role '{member['role']}' lacks capability '{capability}'")
        return {**member, "session_jti": claims["jti"], "auth_method": "session"}

    if os.getenv("TRUSTKERNEL_ALLOW_LEGACY_ACTOR_HEADER", "1") != "1":
        raise HTTPException(401, "Signed member session is required")
    email = (actor_header or "owner@demo.local").strip().lower()
    member = members.get(workspace_id, email)
    if not member:
        raise HTTPException(403, "Actor is not a workspace member")
    if capability and not members.can(workspace_id, email, capability):
        raise HTTPException(403, f"Role '{member['role']}' lacks capability '{capability}'")
    return {**member, "auth_method": "legacy-header"}


@app.get("/")
def index():
    page = FRONTEND_DIR / "index.html"
    return FileResponse(page) if page.exists() else {"name": "TrustKernel", "version": VERSION, "status": "running"}


@app.get("/health")
def health():
    return {"status": "ok", "service": "TrustKernel", "version": VERSION}


@app.get("/ready")
def ready():
    audit = ledger.verify()
    posture = security_posture()
    checks = {
        "database": store.ping(),
        "policy": validate_policy("enterprise-default")["valid"],
        "audit_chain": audit.get("valid", False),
        "security_posture": posture["production_ready"],
    }
    ok = all(checks.values())
    return {"status": "ready" if ok else "degraded", "ready": ok, "checks": checks, "security_posture": posture, "version": VERSION}


@app.get("/api/scenarios")
def scenario_index():
    return [{"id": key, "title": spec["title"], "category": spec.get("category"), "owasp": spec.get("owasp")} for key, spec in SCENARIOS.items()]


@app.post("/api/scenarios/{scenario_id}/run")
def run_scenario(scenario_id: str):
    spec = SCENARIOS.get(scenario_id)
    if not spec:
        raise HTTPException(404, "Scenario not found")
    return evaluate_plan(spec["request"]())


@app.post("/api/evaluate")
def evaluate(request: PlanRequest):
    return evaluate_plan(request)


@app.post("/api/gateway/evaluate")
def gateway(request: GatewayRequest, x_trustkernel_key: str | None = Header(default=None)):
    workspace = _workspace(x_trustkernel_key)
    if workspace:
        quota = quotas.check_and_consume(workspace["id"])
        if not quota["allowed"]:
            telemetry.emit("trustkernel.gateway.rate_limited", workspace_id=workspace["id"], agent_id=request.agent_id, attributes=quota)
            raise HTTPException(429, {"message": "TrustKernel workspace quota exceeded", "quota": quota})
    result = evaluate_plan(
        PlanRequest(agent_id=request.agent_id, intent=request.intent, actions=[request.action], policy_profile=request.policy_profile),
        workspace_id=workspace["id"] if workspace else None,
    )
    if workspace:
        result.metrics["quota"] = quotas.status(workspace["id"])
    return result


# Workspaces, keys and human sessions ---------------------------------------
@app.post("/api/workspaces")
def create_workspace(payload: dict):
    name = str(payload.get("name", "")).strip()
    owner = str(payload.get("owner_email", "owner@demo.local")).strip().lower()
    if not name:
        raise HTTPException(400, "Workspace name is required")
    if "@" not in owner:
        raise HTTPException(400, "owner_email must be an email-like identifier")
    return workspaces.create(name, owner_email=owner)


@app.get("/api/workspaces")
def list_workspaces():
    return workspaces.list()


@app.get("/api/workspaces/{workspace_id}/keys")
def workspace_keys(workspace_id: str, x_trustkernel_key: str | None = Header(default=None)):
    _workspace_match(workspace_id, x_trustkernel_key)
    return workspaces.keys(workspace_id)


@app.post("/api/workspaces/{workspace_id}/keys/rotate")
def rotate_key(workspace_id: str, x_trustkernel_key: str | None = Header(default=None), authorization: str | None = Header(default=None), x_trustkernel_actor: str | None = Header(default=None)):
    _workspace_match(workspace_id, x_trustkernel_key)
    _principal(workspace_id, authorization, x_trustkernel_actor, "workspace.manage")
    return workspaces.rotate_key(workspace_id)


@app.post("/api/workspaces/{workspace_id}/keys/{key_id}/revoke")
def revoke_key(workspace_id: str, key_id: str, x_trustkernel_key: str | None = Header(default=None), authorization: str | None = Header(default=None), x_trustkernel_actor: str | None = Header(default=None)):
    current = _workspace_match(workspace_id, x_trustkernel_key)
    _principal(workspace_id, authorization, x_trustkernel_actor, "workspace.manage")
    if current.get("key_id") == key_id:
        alternatives = [item for item in workspaces.keys(workspace_id) if not item.get("revoked_at") and item["id"] != key_id]
        if not alternatives:
            raise HTTPException(409, "Rotate a replacement key before revoking the only active key")
    if not workspaces.revoke_key(workspace_id, key_id):
        raise HTTPException(404, "Active key not found")
    return {"revoked": True, "key_id": key_id}


@app.get("/api/workspaces/{workspace_id}/usage")
def usage(workspace_id: str, x_trustkernel_key: str | None = Header(default=None)):
    _workspace_match(workspace_id, x_trustkernel_key)
    return quotas.status(workspace_id)


@app.post("/api/workspaces/{workspace_id}/sessions")
def create_session(workspace_id: str, payload: dict, x_trustkernel_key: str | None = Header(default=None)):
    _workspace_match(workspace_id, x_trustkernel_key)
    try:
        issued = sessions.issue(workspace_id, str(payload.get("email", "")).lower(), payload.get("ttl_seconds"))
    except KeyError:
        raise HTTPException(404, "Workspace member not found")
    ledger.append({"event": "MEMBER_SESSION_ISSUED", "workspace_id": workspace_id, "actor": issued["principal"]["sub"], "jti": issued["principal"]["jti"]})
    return issued


@app.get("/api/session/me")
def session_me(authorization: str | None = Header(default=None)):
    if not authorization:
        raise HTTPException(401, "Bearer session is required")
    _, _, token = authorization.partition(" ")
    claims, reason = sessions.verify(token)
    if not claims:
        raise HTTPException(401, f"Invalid member session: {reason}")
    member = members.get(claims["workspace_id"], claims["sub"])
    return {"workspace_id": claims["workspace_id"], "email": claims["sub"], "role": member["role"] if member else claims["role"], "expires_at": claims["exp"], "jti": claims["jti"]}


# RBAC and agent identities --------------------------------------------------
@app.get("/api/workspaces/{workspace_id}/members")
def member_list(workspace_id: str, x_trustkernel_key: str | None = Header(default=None)):
    _workspace_match(workspace_id, x_trustkernel_key)
    return members.list(workspace_id)


@app.post("/api/workspaces/{workspace_id}/members")
def member_upsert(workspace_id: str, payload: dict, x_trustkernel_key: str | None = Header(default=None), authorization: str | None = Header(default=None), x_trustkernel_actor: str | None = Header(default=None)):
    _workspace_match(workspace_id, x_trustkernel_key)
    _principal(workspace_id, authorization, x_trustkernel_actor, "members.manage")
    role = str(payload.get("role", "viewer")).lower()
    if role not in VALID_ROLES:
        raise HTTPException(400, f"Invalid role. Valid roles: {sorted(VALID_ROLES)}")
    return members.upsert(workspace_id, str(payload.get("email", "")).lower(), role)


@app.get("/api/workspaces/{workspace_id}/approval-groups")
def group_list(workspace_id: str, x_trustkernel_key: str | None = Header(default=None)):
    _workspace_match(workspace_id, x_trustkernel_key)
    return approval_groups.list(workspace_id)


@app.get("/api/agents")
def agent_list(x_trustkernel_key: str | None = Header(default=None)):
    workspace = _workspace(x_trustkernel_key)
    return [item.model_dump() for item in agents.list(workspace["id"] if workspace else None)]


@app.post("/api/agents")
def agent_register(agent: AgentIdentity, x_trustkernel_key: str | None = Header(default=None), authorization: str | None = Header(default=None), x_trustkernel_actor: str | None = Header(default=None)):
    workspace = _workspace(x_trustkernel_key)
    if workspace:
        _principal(workspace["id"], authorization, x_trustkernel_actor, "agents.manage")
        agent = agent.model_copy(update={"workspace_id": workspace["id"]})
    return agents.upsert(agent)


# Policy lifecycle -----------------------------------------------------------
@app.get("/api/policies")
def policy_index():
    return list_policies()


@app.get("/api/policies/{profile}")
def policy_get(profile: str):
    return load_policy(profile)


@app.get("/api/policies/{profile}/metadata")
def policy_meta(profile: str):
    return policy_metadata(profile)


@app.post("/api/policy-bundles/{profile}")
def policy_publish(profile: str, payload: dict | None = None, x_trustkernel_key: str | None = Header(default=None), authorization: str | None = Header(default=None), x_trustkernel_actor: str | None = Header(default=None)):
    workspace = _workspace(x_trustkernel_key)
    actor = "system"
    if workspace:
        actor = _principal(workspace["id"], authorization, x_trustkernel_actor, "policies.manage")["email"]
    try:
        if payload and isinstance(payload.get("policy"), dict):
            return publish_policy_document(profile, payload["policy"], created_by=actor, source="api")
        return publish_policy_bundle(profile, created_by=actor)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.get("/api/policy-bundles/{profile}")
def policy_history(profile: str):
    return list_policy_bundles(profile)


@app.get("/api/workspaces/{workspace_id}/policies/{profile}/active")
def policy_active(workspace_id: str, profile: str, x_trustkernel_key: str | None = Header(default=None)):
    _workspace_match(workspace_id, x_trustkernel_key)
    return active_policy_bundle(workspace_id, profile) or {"profile": profile, "source": "filesystem", "metadata": policy_metadata(profile)}


@app.post("/api/workspaces/{workspace_id}/policies/{profile}/activate/{bundle_id}")
def policy_activate(workspace_id: str, profile: str, bundle_id: str, x_trustkernel_key: str | None = Header(default=None), authorization: str | None = Header(default=None), x_trustkernel_actor: str | None = Header(default=None)):
    _workspace_match(workspace_id, x_trustkernel_key)
    if os.getenv("TRUSTKERNEL_REQUIRE_POLICY_APPROVAL", "0") == "1" or os.getenv("TRUSTKERNEL_ENV", "development").lower() == "production":
        raise HTTPException(409, "Direct policy activation is disabled; use a governed policy-change request")
    actor = _principal(workspace_id, authorization, x_trustkernel_actor, "policies.manage")
    return activate_policy_bundle(workspace_id, profile, bundle_id, activated_by=actor["email"])


@app.get("/api/workspaces/{workspace_id}/policy-changes")
def policy_change_list(workspace_id: str, x_trustkernel_key: str | None = Header(default=None), authorization: str | None = Header(default=None), x_trustkernel_actor: str | None = Header(default=None)):
    _workspace_match(workspace_id, x_trustkernel_key)
    _principal(workspace_id, authorization, x_trustkernel_actor, "read")
    return policy_changes.list(workspace_id)


@app.post("/api/workspaces/{workspace_id}/policy-changes/{profile}/{bundle_id}")
def policy_change_propose(workspace_id: str, profile: str, bundle_id: str, payload: dict | None = None, x_trustkernel_key: str | None = Header(default=None), authorization: str | None = Header(default=None), x_trustkernel_actor: str | None = Header(default=None)):
    _workspace_match(workspace_id, x_trustkernel_key)
    actor = _principal(workspace_id, authorization, x_trustkernel_actor, "policies.manage")
    try:
        item = policy_changes.propose(workspace_id, profile, bundle_id, actor["email"], (payload or {}).get("approval_group", "security-approvers"))
    except KeyError:
        raise HTTPException(404, "Policy bundle not found")
    ledger.append({"event": "POLICY_CHANGE_PROPOSED", "workspace_id": workspace_id, "request_id": item["id"], "actor": actor["email"]})
    return item


@app.post("/api/workspaces/{workspace_id}/policy-changes/{request_id}/vote/{decision}")
def policy_change_vote(workspace_id: str, request_id: str, decision: str, x_trustkernel_key: str | None = Header(default=None), authorization: str | None = Header(default=None), x_trustkernel_actor: str | None = Header(default=None)):
    _workspace_match(workspace_id, x_trustkernel_key)
    actor = _principal(workspace_id, authorization, x_trustkernel_actor, "approvals.resolve")
    item = policy_changes.get(request_id)
    if not item or item["workspace_id"] != workspace_id:
        raise HTTPException(404, "Policy change request not found")
    try:
        return policy_changes.vote(request_id, actor["email"], decision)
    except PermissionError as exc:
        raise HTTPException(403, str(exc))
    except ValueError as exc:
        raise HTTPException(409, str(exc))


# MCP and workload identity --------------------------------------------------
@app.get("/api/mcp/servers")
def mcp_list(x_trustkernel_key: str | None = Header(default=None)):
    workspace = _workspace(x_trustkernel_key, True)
    return mcp_registry.list(workspace["id"])


@app.post("/api/mcp/servers")
def mcp_register(payload: dict, x_trustkernel_key: str | None = Header(default=None), authorization: str | None = Header(default=None), x_trustkernel_actor: str | None = Header(default=None)):
    workspace = _workspace(x_trustkernel_key, True)
    _principal(workspace["id"], authorization, x_trustkernel_actor, "mcp.manage")
    uri = str(payload.get("canonical_uri", "")).rstrip("/")
    if not str(payload.get("name", "")).strip() or not uri.startswith(("http://", "https://")):
        raise HTTPException(400, "name and canonical http(s) URI are required")
    return mcp_registry.register(
        workspace["id"], name=str(payload["name"]), canonical_uri=uri,
        manifest=payload.get("manifest"), manifest_sha256=payload.get("manifest_sha256"),
        issuer=payload.get("issuer"), allowed_scopes=list(payload.get("allowed_scopes", [])),
        status=str(payload.get("status", "ACTIVE")),
    )


@app.get("/api/workload-identities")
def workload_list(agent_id: str | None = None, x_trustkernel_key: str | None = Header(default=None)):
    workspace = _workspace(x_trustkernel_key, True)
    return workload_identities.list(workspace["id"], agent_id)


@app.post("/api/workload-identities")
def workload_register(payload: dict, x_trustkernel_key: str | None = Header(default=None), authorization: str | None = Header(default=None), x_trustkernel_actor: str | None = Header(default=None)):
    workspace = _workspace(x_trustkernel_key, True)
    actor = _principal(workspace["id"], authorization, x_trustkernel_actor, "agents.manage")
    agent_id = str(payload.get("agent_id", ""))
    if not agents.get(agent_id, workspace["id"]):
        raise HTTPException(404, "Workspace agent not found")
    try:
        item = workload_identities.register_public_key(workspace["id"], agent_id, str(payload.get("public_key_pem", "")))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    ledger.append({"event": "WORKLOAD_KEY_REGISTERED", "workspace_id": workspace["id"], "agent_id": agent_id, "key_id": item["id"], "actor": actor["email"]})
    return item


@app.post("/api/workload-identities/demo-keypair")
def workload_demo_keypair(payload: dict, x_trustkernel_key: str | None = Header(default=None), authorization: str | None = Header(default=None), x_trustkernel_actor: str | None = Header(default=None)):
    if os.getenv("TRUSTKERNEL_ENV", "development").lower() == "production":
        raise HTTPException(403, "Demo key generation is disabled in production")
    workspace = _workspace(x_trustkernel_key, True)
    _principal(workspace["id"], authorization, x_trustkernel_actor, "agents.manage")
    agent_id = str(payload.get("agent_id", ""))
    if not agents.get(agent_id, workspace["id"]):
        raise HTTPException(404, "Workspace agent not found")
    return workload_identities.generate_demo_keypair(workspace["id"], agent_id)


@app.post("/api/a2a/sign")
def sign_a2a(payload: dict, x_trustkernel_key: str | None = Header(default=None)):
    workspace = _workspace(x_trustkernel_key, True)
    sender, recipient = str(payload.get("sender", "")), str(payload.get("recipient", ""))
    if not agents.get(sender, workspace["id"]) or not agents.get(recipient, workspace["id"]):
        raise HTTPException(400, "Sender and recipient must be registered agents")
    nonce = str(payload.get("nonce") or secrets.token_urlsafe(16))
    timestamp = int(payload.get("timestamp") or time.time())
    body = payload.get("payload", {})
    return {"sender": sender, "recipient": recipient, "nonce": nonce, "timestamp": timestamp, "payload": body, "signature": message_security.sign(workspace["id"], sender, recipient, nonce, timestamp, body)}


# Evidence, incidents, approvals and observability --------------------------
@app.get("/api/audit")
def audit(x_trustkernel_key: str | None = Header(default=None)):
    workspace = _workspace(x_trustkernel_key)
    return ledger.list(workspace["id"] if workspace else None)


@app.get("/api/audit/verify")
def audit_verify():
    return ledger.verify()


@app.get("/api/incidents")
def incident_list(x_trustkernel_key: str | None = Header(default=None)):
    workspace = _workspace(x_trustkernel_key)
    items = incidents.list(workspace["id"] if workspace else None)
    return items if workspace else [item for item in items if item.get("workspace_id") is None]


@app.get("/api/incidents/{incident_id}/investigation")
def incident_investigation(incident_id: str, x_trustkernel_key: str | None = Header(default=None)):
    item = incidents.get(incident_id)
    if not item:
        raise HTTPException(404, "Incident not found")
    if item.get("workspace_id"):
        workspace = _workspace(x_trustkernel_key, True)
        if workspace["id"] != item["workspace_id"]:
            raise HTTPException(403, "Incident belongs to another workspace")
    return incidents.investigation(incident_id)


@app.get("/api/approvals")
def approval_list(x_trustkernel_key: str | None = Header(default=None)):
    workspace = _workspace(x_trustkernel_key)
    items = approvals.list()
    if not workspace:
        return [item for item in items if item.get("payload", {}).get("workspace_id") is None]
    return [item for item in items if item.get("payload", {}).get("workspace_id") == workspace["id"]]


@app.post("/api/approvals/{audit_id}/{resolution}")
def approval_resolve(audit_id: str, resolution: str, x_trustkernel_key: str | None = Header(default=None), x_trustkernel_actor: str | None = Header(default=None), x_trustkernel_role: str | None = Header(default=None)):
    normalized = resolution.upper()
    if normalized not in {"APPROVE", "REJECT"}:
        raise HTTPException(400, "Resolution must be APPROVE or REJECT")
    pending = approvals.get(audit_id)
    if not pending:
        raise HTTPException(404, "Approval request not found")
    workspace_id = pending.get("payload", {}).get("workspace_id")
    group = pending.get("payload", {}).get("required_approval_group", "security-approvers")
    if workspace_id:
        workspace = _workspace(x_trustkernel_key, True)
        if workspace["id"] != workspace_id:
            raise HTTPException(403, "Approval belongs to another workspace")
        actor = (x_trustkernel_actor or "owner@demo.local").lower()
        member = members.get(workspace_id, actor)
        if not member or not approval_groups.permits(workspace_id, group, actor):
            raise HTTPException(403, f"Actor is not permitted by approval group '{group}'")
        role = member["role"]
    else:
        actor, role = x_trustkernel_actor or "demo-operator", (x_trustkernel_role or "approver").lower()
    item = approvals.resolve(audit_id, normalized, actor=actor, role=role)
    ledger.append({"event": "HUMAN_APPROVAL", "audit_id": audit_id, "resolution": normalized, "actor": actor, "role": role, "approval_group": group})
    return item


@app.get("/api/telemetry/export")
def telemetry_export(limit: int = 500, x_trustkernel_key: str | None = Header(default=None)):
    workspace = _workspace(x_trustkernel_key, True)
    return telemetry.export(workspace["id"], limit)


@app.get("/api/telemetry/otlp")
def telemetry_otlp(limit: int = 500, x_trustkernel_key: str | None = Header(default=None)):
    workspace = _workspace(x_trustkernel_key, True)
    return otlp.export_json(workspace["id"], limit)


@app.post("/api/benchmarks/run")
def benchmark_run(payload: dict, x_trustkernel_key: str | None = Header(default=None)):
    workspace = _workspace(x_trustkernel_key)
    cases = payload.get("cases", [])
    if not isinstance(cases, list) or len(cases) > 500:
        raise HTTPException(400, "cases must be a list with at most 500 entries")
    return benchmark_adapter.run_cases(cases, workspace["id"] if workspace else None)


@app.get("/api/security/posture")
def posture():
    return security_posture()


@app.get("/api/status")
def status():
    audit_state = ledger.verify()
    meta = policy_metadata("enterprise-default")
    return {
        "service": "TrustKernel",
        "version": VERSION,
        "agents": len(agents.list()),
        "audit_entries": audit_state.get("entries", 0),
        "audit_chain_valid": audit_state.get("valid", False),
        "pending_approvals": len([x for x in approvals.list() if x.get("status") == "PENDING"]),
        "open_incidents": len([x for x in incidents.list() if x.get("status") != "RESOLVED"]),
        "policy_profile": meta["name"],
        "policy_version": meta["version"],
        "policy_sha256": meta["sha256"],
        "database_ready": store.ping(),
        "security_posture": security_posture(),
    }


@app.post("/api/judge-demo/run")
def judge_demo():
    ids = ["prompt-injection", "mcp-poisoned-tool", "unsafe-sql", "high-value-payment", "safe-analytics"]
    sequence = []
    for scenario_id in ids:
        spec = SCENARIOS[scenario_id]
        result = evaluate_plan(spec["request"]())
        sequence.append({
            "scenario_id": scenario_id,
            "title": spec["title"],
            "decision": result.decision.value,
            "risk_score": result.risk_score,
            "audit_id": result.audit_id,
            "incident_id": result.metrics.get("incident_id"),
            "repairs": result.metrics.get("repairs_proposed", 0),
            "approval_required": result.approval_required,
        })
    return {"mode": "JUDGE_DEMO", "sequence": sequence, "audit_chain": ledger.verify(), "message": "Five deterministic scenarios executed through the live TrustKernel v1.2 enforcement path."}
