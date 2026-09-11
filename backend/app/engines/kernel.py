from __future__ import annotations
import time
from typing import List, Optional
from ..models import PlanRequest, EvaluationResult, ActionResult, Finding, Decision, Action
from .graph import build_action_graph, graph_patterns
from .taint import TaintState
from .policy import evaluate_action
from .risk import action_risk, aggregate_risk
from .simulator import simulate
from ..services.audit import ledger
from ..services.approvals import approvals
from ..services.agents import agents
from ..services.policies import load_policy, policy_metadata
from ..services.incidents import incidents
from ..services.telemetry import telemetry
from ..services.mcp_registry import mcp_registry
from ..services.messaging import message_security
from ..services.workload_identity import workload_identities

PRIORITY = {Decision.ALLOW: 0, Decision.ALLOW_WITH_LOG: 1, Decision.REWRITE: 2, Decision.REQUIRE_APPROVAL: 3, Decision.BLOCK: 4}


def _prepare_action(action: Action, workspace_id: Optional[str], authenticated_agent_id: Optional[str]) -> Action:
    prepared = action
    prepared, _ = mcp_registry.enrich(prepared, workspace_id)

    if workspace_id and prepared.tool == "agent_message" and prepared.operation.lower() == "send":
        metadata = dict(prepared.metadata)
        sender = str(metadata.get("claimed_sender") or authenticated_agent_id or "")
        recipient = prepared.resource
        metadata["recipient_registered"] = agents.get(recipient, workspace_id) is not None
        nonce = str(metadata.get("message_nonce", ""))
        timestamp = int(metadata.get("message_timestamp", 0) or 0)
        signature = str(metadata.get("message_signature", ""))
        payload = metadata.get("message_payload", {})
        if nonce or signature or timestamp:
            workload_key_id = str(metadata.get("workload_key_id", ""))
            if workload_key_id:
                valid, reason = workload_identities.verify_and_mark(
                    workspace_id=workspace_id, key_id=workload_key_id, sender=sender, recipient=recipient,
                    nonce=nonce, timestamp=timestamp, payload=payload, signature=signature,
                )
                metadata["signature_scheme"] = "Ed25519"
                metadata["workload_key_id"] = workload_key_id
            else:
                valid, reason = message_security.verify_and_mark(
                    workspace_id=workspace_id,
                    sender=sender,
                    recipient=recipient,
                    nonce=nonce,
                    timestamp=timestamp,
                    payload=payload,
                    signature=signature,
                )
                metadata["signature_scheme"] = "HMAC-SHA256"
            metadata["signature_valid"] = valid
            metadata["replay_detected"] = reason == "replay_detected"
            metadata["message_fresh"] = reason not in {"stale_timestamp", "missing_nonce"}
            metadata["signature_reason"] = reason
        prepared = prepared.model_copy(update={"metadata": metadata})
    return prepared


def evaluate_plan(request: PlanRequest, workspace_id: Optional[str] = None) -> EvaluationResult:
    started = time.perf_counter()
    policy = load_policy(request.policy_profile, workspace_id)
    policy_meta = policy_metadata(request.policy_profile, workspace_id)
    raw_agent = agents.get(request.agent_id) if request.agent_id else None
    workspace_mismatch = bool(workspace_id and raw_agent and raw_agent.workspace_id not in {None, workspace_id})
    agent = None if workspace_mismatch else (agents.get(request.agent_id, workspace_id) if request.agent_id else None)
    taint = TaintState()
    action_results: List[ActionResult] = []
    findings: List[Finding] = []
    decisions: List[Decision] = []
    scores: List[int] = []
    prepared_actions: List[Action] = []

    for raw_action in request.actions:
        action = _prepare_action(raw_action, workspace_id, request.agent_id)
        prepared_actions.append(action)
        action_taints = taint.observe(action)
        if workspace_mismatch:
            decision, reasons, rewritten, matched = (
                Decision.BLOCK,
                [f"Agent '{request.agent_id}' belongs to a different workspace and cannot execute here."],
                None,
                ["TK-WORKSPACE-SCOPE-001"],
            )
        else:
            decision, reasons, rewritten, matched = evaluate_action(
                action=action,
                intent=request.intent,
                action_taints=action_taints,
                policy=policy,
                agent=agent,
            )
        risk = action_risk(action, decision)
        impact = simulate(rewritten or action)
        reasons = reasons + [f"Consequence simulation: {impact['predicted']}."]
        action_results.append(ActionResult(action=action, decision=decision, risk=risk, reasons=reasons, rewritten_action=rewritten, matched_policies=matched))
        decisions.append(decision)
        scores.append(risk)
        if decision in {Decision.REWRITE, Decision.REQUIRE_APPROVAL, Decision.BLOCK}:
            findings.append(Finding(
                code=matched[0] if matched else f"TK-{decision.value}",
                policy_id=matched[0] if matched else None,
                severity="CRITICAL" if decision == Decision.BLOCK else "HIGH" if decision == Decision.REQUIRE_APPROVAL else "MEDIUM",
                title=decision.value.replace("_", " ").title(),
                detail=" ".join(reasons),
                action_ids=[action.id],
            ))

    effective_actions = [result.rewritten_action or result.action for result in action_results]
    effective_taint = TaintState()
    for effective_action in effective_actions:
        effective_taint.observe(effective_action)

    patterns = graph_patterns(effective_actions, effective_taint.by_action)
    for pattern in patterns:
        if pattern["type"] == "sensitive_to_external_sink":
            findings.append(Finding(
                code="TK-DATA-EGRESS-CHAIN-001", policy_id="TK-DLP-SECRET-001", severity="CRITICAL",
                title="Sensitive-data egress chain detected",
                detail=f"Sensitive labels {pattern.get('labels', [])} reach external sink '{pattern['destination']}'.",
                action_ids=[pattern["source"], pattern["sink"]],
            ))
            scores.append(100)
            decisions.append(Decision.BLOCK)
        elif pattern["type"] == "untrusted_influence_to_side_effect":
            findings.append(Finding(
                code="TK-UNTRUSTED-CHAIN-001", policy_id="TK-UNTRUSTED-SIDE-EFFECT-001", severity="HIGH",
                title="Untrusted influence reaches consequential action",
                detail=f"Untrusted content influences side effect to '{pattern['destination']}'.",
                action_ids=[pattern["source"], pattern["sink"]],
            ))

    final_decision = max(decisions or [Decision.ALLOW], key=lambda d: PRIORITY[d])
    risk_score = aggregate_risk(scores)
    taint_snapshot = effective_taint.snapshot()
    graph = build_action_graph(effective_actions, taint_snapshot.get("by_action", {}))
    graph["patterns"] = patterns
    graph["taint"] = taint_snapshot

    audit = ledger.append({
        "workspace_id": workspace_id,
        "agent": agent.model_dump() if agent else (raw_agent.model_dump() if raw_agent else None),
        "policy": policy_meta,
        "intent": request.intent.model_dump(),
        "decision": final_decision.value,
        "risk_score": risk_score,
        "findings": [f.model_dump() for f in findings],
        "actions": [a.model_dump() for a in prepared_actions],
        "action_results": [r.model_dump() for r in action_results],
        "graph": graph,
    })

    required_group = None
    if final_decision == Decision.REQUIRE_APPROVAL:
        required_group = "finance-approvers" if any(a.tool == "payment" for a in prepared_actions) else "security-approvers"
        approvals.create(audit["id"], {
            "workspace_id": workspace_id,
            "agent_id": request.agent_id,
            "risk_score": risk_score,
            "intent": request.intent.user_request,
            "actions": [a.model_dump() for a in prepared_actions],
            "required_approval_group": required_group,
            "policy": policy_meta,
        })

    incident = incidents.create_from_evaluation(
        audit_id=audit["id"], workspace_id=workspace_id, decision=final_decision.value, risk_score=risk_score,
        findings=[f.model_dump() for f in findings], agent_id=request.agent_id, graph=graph,
        action_results=[r.model_dump() for r in action_results], policy=policy_meta,
    )
    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    telemetry.emit(
        "trustkernel.agent.action.evaluated", workspace_id=workspace_id, agent_id=request.agent_id,
        attributes={
            "gen_ai.agent.id": request.agent_id,
            "trustkernel.decision": final_decision.value,
            "trustkernel.risk_score": risk_score,
            "trustkernel.policy.name": policy_meta["name"],
            "trustkernel.policy.version": policy_meta["version"],
            "trustkernel.policy.sha256": policy_meta["sha256"],
            "trustkernel.policy.bundle_id": policy_meta.get("bundle_id"),
            "trustkernel.audit_id": audit["id"],
            "trustkernel.incident_id": incident["id"] if incident else None,
            "trustkernel.approval.group": required_group,
            "trustkernel.evaluation.duration_ms": elapsed_ms,
        },
    )

    return EvaluationResult(
        decision=final_decision,
        risk_score=risk_score,
        summary=f"TrustKernel evaluated {len(request.actions)} action(s) for agent {request.agent_id or 'unregistered'} and returned {final_decision.value}.",
        findings=findings,
        action_results=action_results,
        graph=graph,
        audit_id=audit["id"],
        approval_required=final_decision == Decision.REQUIRE_APPROVAL,
        metrics={
            "actions_evaluated": len(request.actions),
            "evaluation_latency_ms": elapsed_ms,
            "taint_labels": sorted(effective_taint.labels),
            "agent_registered": raw_agent is not None,
            "workspace_id": workspace_id,
            "workspace_scope_valid": not workspace_mismatch,
            "policy_profile": policy_meta["name"],
            "policy_version": policy_meta["version"],
            "policy_sha256": policy_meta["sha256"],
            "policy_bundle_id": policy_meta.get("bundle_id"),
            "policy_signature_valid": policy_meta.get("signature_valid"),
            "repairs_proposed": sum(1 for item in action_results if item.rewritten_action is not None),
            "incident_id": incident["id"] if incident else None,
            "required_approval_group": required_group,
        },
    )
