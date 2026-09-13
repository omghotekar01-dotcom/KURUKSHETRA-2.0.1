from __future__ import annotations
import time
import uuid
from typing import Any, Dict, List, Optional
from .storage import store


_REMEDIATIONS = {
    "TK-MCP-REGISTRY-001": "Register the MCP server in the workspace trust registry and pin its manifest before use.",
    "TK-MCP-PROVENANCE-001": "Verify MCP server provenance and require a pinned manifest hash.",
    "TK-PROVENANCE-HASH-001": "Restore the approved tool manifest or re-register the reviewed manifest hash before execution.",
    "TK-MCP-TOKEN-PASSTHROUGH-001": "Use a separate downstream token; never forward the client token to another resource.",
    "TK-MCP-AUDIENCE-001": "Issue a resource-bound access token for the canonical MCP server URI.",
    "TK-MCP-SCOPE-001": "Reduce requested scopes to the registry allowlist and use step-up authorization for additional scopes.",
    "TK-A2A-REPLAY-001": "Reject the message and rotate/review sender credentials if replay attempts persist.",
    "TK-A2A-STALE-001": "Use a fresh timestamp and nonce within the accepted message window.",
    "TK-A2A-SIGNATURE-001": "Verify workload identity and message signature before accepting agent-to-agent instructions.",
    "TK-DLP-SECRET-001": "Redact or aggregate sensitive values before any external transfer.",
    "TK-IAM-TOOL-001": "Reduce the agent tool grant to the minimum set required for its task.",
    "TK-IAM-OP-001": "Remove the unauthorized operation from the execution plan or request explicit authorization.",
    "TK-WORKSPACE-SCOPE-001": "Use an agent identity registered to the current workspace.",
    "TK-PAYMENT-APPROVAL-001": "Route the transaction to the configured finance approval group.",
}


def _causal_chain(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build a deterministic investigation chain from recorded evidence only.

    This is an explanatory projection for operators; it does not infer hidden causes or
    claim that a finding caused another finding unless that relationship is present in
    the captured graph patterns.
    """
    findings = payload.get("findings", []) or []
    graph = payload.get("graph_snapshot", {}) or {}
    patterns = graph.get("patterns", []) or []
    chain: List[Dict[str, Any]] = []

    if payload.get("agent_id"):
        chain.append(
            {
                "stage": "workload",
                "label": f"Agent {payload['agent_id']}",
                "evidence_type": "recorded",
            }
        )

    for index, finding in enumerate(findings, start=1):
        chain.append(
            {
                "stage": "finding",
                "label": finding.get("title") or finding.get("code") or f"Finding {index}",
                "code": finding.get("code"),
                "severity": finding.get("severity"),
                "evidence_type": "recorded",
            }
        )

    for index, pattern in enumerate(patterns, start=1):
        if isinstance(pattern, dict):
            label = pattern.get("label") or pattern.get("name") or pattern.get("type") or f"Attack path {index}"
        else:
            label = str(pattern)
        chain.append(
            {
                "stage": "attack_path",
                "label": label,
                "evidence_type": "graph_snapshot",
            }
        )

    chain.append(
        {
            "stage": "decision",
            "label": payload.get("decision") or "UNKNOWN",
            "risk_score": payload.get("risk_score"),
            "evidence_type": "recorded",
        }
    )
    return chain


def _remediation_timeline(item: Dict[str, Any], payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return an ordered incident timeline while separating facts from recommendations."""
    timeline: List[Dict[str, Any]] = [
        {
            "sequence": 1,
            "phase": "detect",
            "state": "recorded",
            "label": "TrustKernel evaluation created the incident",
            "timestamp": item.get("created_at"),
        }
    ]

    decision = payload.get("decision")
    if decision in {"BLOCK", "REQUIRE_APPROVAL"}:
        timeline.append(
            {
                "sequence": len(timeline) + 1,
                "phase": "contain",
                "state": "recorded",
                "label": "Execution blocked" if decision == "BLOCK" else "Execution held for approval",
                "timestamp": item.get("created_at"),
            }
        )

    for action in payload.get("action_results", []) or []:
        timeline.append(
            {
                "sequence": len(timeline) + 1,
                "phase": "action",
                "state": "recorded",
                "label": action.get("action") or action.get("name") or action.get("status") or "Recorded action result",
                "result": action,
            }
        )

    for remediation in payload.get("recommended_remediation", []) or []:
        timeline.append(
            {
                "sequence": len(timeline) + 1,
                "phase": "remediate",
                "state": "recommended",
                "label": remediation,
            }
        )

    timeline.append(
        {
            "sequence": len(timeline) + 1,
            "phase": "verify",
            "state": "recommended",
            "label": "Re-run the affected workflow and confirm policy, identity, provenance, and audit evidence before closure.",
        }
    )
    return timeline


class IncidentService:
    def create_from_evaluation(
        self,
        *,
        audit_id: str,
        workspace_id: Optional[str],
        decision: str,
        risk_score: int,
        findings: List[Dict[str, Any]],
        agent_id: Optional[str],
        graph: Optional[Dict[str, Any]] = None,
        action_results: Optional[List[Dict[str, Any]]] = None,
        policy: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        if decision not in {"BLOCK", "REQUIRE_APPROVAL"} and risk_score < 70:
            return None
        severity = "CRITICAL" if decision == "BLOCK" or risk_score >= 90 else "HIGH"
        title = findings[0]["title"] if findings else f"TrustKernel {decision.replace('_', ' ').title()}"
        now = time.time()
        codes = [item.get("code") for item in findings if item.get("code")]
        remediations = [_REMEDIATIONS[code] for code in codes if code in _REMEDIATIONS]
        item = {
            "id": f"INC-{uuid.uuid4().hex[:10].upper()}",
            "audit_id": audit_id,
            "workspace_id": workspace_id,
            "severity": severity,
            "status": "OPEN",
            "title": title,
            "created_at": now,
            "updated_at": now,
            "payload": {
                "decision": decision,
                "risk_score": risk_score,
                "findings": findings,
                "agent_id": agent_id,
                "policy": policy or {},
                "graph_snapshot": graph or {},
                "action_results": action_results or [],
                "recommended_remediation": remediations,
            },
        }
        store.create_incident(item)
        return item

    def list(self, workspace_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return store.incidents(workspace_id)

    def get(self, incident_id: str) -> Optional[Dict[str, Any]]:
        return store.incident(incident_id)

    def set_status(self, incident_id: str, status: str) -> Optional[Dict[str, Any]]:
        return store.update_incident_status(incident_id, status, time.time())

    def investigation(self, incident_id: str) -> Optional[Dict[str, Any]]:
        item = self.get(incident_id)
        if not item:
            return None
        payload = item.get("payload", {})
        graph = payload.get("graph_snapshot", {})
        return {
            "incident_id": item["id"],
            "status": item["status"],
            "severity": item["severity"],
            "agent_id": payload.get("agent_id"),
            "decision": payload.get("decision"),
            "risk_score": payload.get("risk_score"),
            "policy": payload.get("policy", {}),
            "findings": payload.get("findings", []),
            "attack_paths": graph.get("patterns", []),
            "graph": graph,
            "causal_chain": _causal_chain(payload),
            "remediation_timeline": _remediation_timeline(item, payload),
            "recommended_remediation": payload.get("recommended_remediation", []),
            "evidence": {
                "audit_id": item["audit_id"],
                "action_results": payload.get("action_results", []),
                "workspace_id": item.get("workspace_id"),
            },
        }


incidents = IncidentService()
