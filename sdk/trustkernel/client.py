from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable, Dict, Generic, Optional, TypeVar
import httpx

T = TypeVar("T")


@dataclass(frozen=True)
class TrustKernelDecision:
    decision: str
    risk_score: int
    audit_id: str
    approval_required: bool
    raw: Dict[str, Any]

    @property
    def allowed(self) -> bool:
        return self.decision in {"ALLOW", "ALLOW_WITH_LOG", "REWRITE"}

    @property
    def effective_action(self) -> Dict[str, Any]:
        results = self.raw.get("action_results") or []
        if not results:
            return {}
        first = results[0]
        return first.get("rewritten_action") or first.get("action") or {}


@dataclass(frozen=True)
class GuardedExecution(Generic[T]):
    decision: TrustKernelDecision
    executed: bool
    value: Optional[T] = None


class TrustKernelClient:
    """Framework-agnostic client for the TrustKernel runtime enforcement gateway."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000", api_key: str | None = None, session_token: str | None = None, timeout: float = 5.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session_token = session_token
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self.api_key:
            headers["X-TrustKernel-Key"] = self.api_key
        if self.session_token:
            headers["Authorization"] = f"Bearer {self.session_token}"
        return headers

    def _request(self, method: str, path: str, **kwargs) -> Any:
        headers = {**self._headers(), **kwargs.pop("headers", {})}
        response = httpx.request(method, f"{self.base_url}{path}", headers=headers, timeout=self.timeout, **kwargs)
        response.raise_for_status()
        return response.json()

    def evaluate_action(
        self, *, agent_id: str, user_request: str, tool: str, operation: str,
        action_id: str = "sdk-action-1", resource: str = "", destination: str = "",
        amount: Optional[float] = None, allowed_tools: Optional[list[str]] = None,
        constraints: Optional[Dict[str, Any]] = None, source_trust: str = "UNKNOWN",
        sensitivity: str = "PUBLIC", metadata: Optional[Dict[str, Any]] = None,
        policy_profile: str = "enterprise-default",
    ) -> TrustKernelDecision:
        payload = {
            "agent_id": agent_id,
            "policy_profile": policy_profile,
            "intent": {"user_request": user_request, "allowed_tools": allowed_tools or [tool], "constraints": constraints or {}},
            "action": {
                "id": action_id, "tool": tool, "operation": operation, "resource": resource,
                "destination": destination, "amount": amount, "source_trust": source_trust,
                "sensitivity": sensitivity, "metadata": metadata or {},
            },
        }
        data = self._request("POST", "/api/gateway/evaluate", json=payload)
        return TrustKernelDecision(decision=data["decision"], risk_score=data["risk_score"], audit_id=data["audit_id"], approval_required=data["approval_required"], raw=data)

    def execute_guarded(self, executor: Callable[[Dict[str, Any]], T], **evaluation_kwargs: Any) -> GuardedExecution[T]:
        decision = self.evaluate_action(**evaluation_kwargs)
        if not decision.allowed:
            return GuardedExecution(decision=decision, executed=False, value=None)
        return GuardedExecution(decision=decision, executed=True, value=executor(decision.effective_action))

    def incidents(self) -> list[Dict[str, Any]]:
        return self._request("GET", "/api/incidents")

    def telemetry(self, limit: int = 100) -> Dict[str, Any]:
        return self._request("GET", f"/api/telemetry/export?limit={int(limit)}")

    def verify_audit(self) -> Dict[str, Any]:
        return self._request("GET", "/api/audit/verify")

    def policy_metadata(self, profile: str = "enterprise-default") -> Dict[str, Any]:
        return self._request("GET", f"/api/policies/{profile}/metadata")

    def usage(self, workspace_id: str) -> Dict[str, Any]:
        return self._request("GET", f"/api/workspaces/{workspace_id}/usage")

    def otlp_json(self, limit: int = 100) -> Dict[str, Any]:
        return self._request("GET", f"/api/telemetry/otlp?limit={int(limit)}")

    def incident_investigation(self, incident_id: str) -> Dict[str, Any]:
        return self._request("GET", f"/api/incidents/{incident_id}/investigation")

    def policy_history(self, profile: str = "enterprise-default") -> list[Dict[str, Any]]:
        return self._request("GET", f"/api/policy-bundles/{profile}")

    def register_mcp_server(self, *, name: str, canonical_uri: str, manifest: str = "", issuer: str | None = None, allowed_scopes: Optional[list[str]] = None, actor: str = "owner@demo.local") -> Dict[str, Any]:
        return self._request("POST", "/api/mcp/servers", headers={"X-TrustKernel-Actor": actor}, json={"name": name, "canonical_uri": canonical_uri, "manifest": manifest, "issuer": issuer, "allowed_scopes": allowed_scopes or []})

    def create_member_session(self, workspace_id: str, email: str, ttl_seconds: int | None = None, *, adopt: bool = True) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"email": email}
        if ttl_seconds is not None:
            payload["ttl_seconds"] = ttl_seconds
        result = self._request("POST", f"/api/workspaces/{workspace_id}/sessions", json=payload)
        if adopt:
            self.session_token = result["token"]
        return result

    def policy_changes(self, workspace_id: str) -> list[Dict[str, Any]]:
        return self._request("GET", f"/api/workspaces/{workspace_id}/policy-changes")

    def propose_policy_change(self, workspace_id: str, profile: str, bundle_id: str, approval_group: str = "security-approvers") -> Dict[str, Any]:
        return self._request("POST", f"/api/workspaces/{workspace_id}/policy-changes/{profile}/{bundle_id}", json={"approval_group": approval_group})

    def vote_policy_change(self, workspace_id: str, request_id: str, decision: str) -> Dict[str, Any]:
        return self._request("POST", f"/api/workspaces/{workspace_id}/policy-changes/{request_id}/vote/{decision.upper()}")

    def workload_identities(self, agent_id: str | None = None) -> list[Dict[str, Any]]:
        suffix = f"?agent_id={agent_id}" if agent_id else ""
        return self._request("GET", f"/api/workload-identities{suffix}")

    def register_workload_identity(self, *, agent_id: str, public_key_pem: str) -> Dict[str, Any]:
        return self._request("POST", "/api/workload-identities", json={"agent_id": agent_id, "public_key_pem": public_key_pem})

    def security_posture(self) -> Dict[str, Any]:
        return self._request("GET", "/api/security/posture")

    def sign_agent_message(self, *, sender: str, recipient: str, payload: Dict[str, Any], nonce: str | None = None) -> Dict[str, Any]:
        body: Dict[str, Any] = {"sender": sender, "recipient": recipient, "payload": payload}
        if nonce:
            body["nonce"] = nonce
        return self._request("POST", "/api/a2a/sign", json=body)
