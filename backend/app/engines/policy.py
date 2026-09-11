from __future__ import annotations
from typing import List, Tuple, Optional, Set, Dict, Any
from ..models import Action, Decision, Intent, AgentIdentity
from .repair import repair_action

EXTERNAL_SINKS = {"send", "post", "upload", "publish", "push"}


def _domain_trusted(destination: str, trusted_domains: Set[str]) -> bool:
    if not destination:
        return True
    return any(destination == domain or destination.endswith(f".{domain}") for domain in trusted_domains)


def evaluate_action(
    action: Action,
    intent: Intent,
    action_taints: Set[str],
    policy: Dict[str, Any],
    agent: Optional[AgentIdentity] = None,
) -> Tuple[Decision, List[str], Optional[Action], List[str]]:
    reasons: List[str] = []
    matched: List[str] = []
    op = action.operation.lower()

    identity_policy = policy.get("identity", {})
    if agent is None and identity_policy.get("require_registered_agent"):
        if action.metadata.get("allow_unregistered_demo") is not True:
            matched.append("TK-IDENTITY-001")
            return Decision.BLOCK, ["No registered agent identity is attached to this action."], None, matched

    if agent is not None and identity_policy.get("enforce_tool_allowlist") and action.tool not in agent.allowed_tools:
        matched.append("TK-IAM-TOOL-001")
        return Decision.BLOCK, [f"Agent '{agent.id}' is not authorized to use tool '{action.tool}'."], None, matched

    if intent.allowed_tools and action.tool not in intent.allowed_tools:
        matched.append("TK-INTENT-SCOPE-001")
        return Decision.BLOCK, [f"Tool '{action.tool}' is outside the user's authorized tool set."], None, matched

    provenance_policy = policy.get("provenance", {})
    mcp_policy = policy.get("mcp", {})
    source_kind = str(action.metadata.get("source_kind", "")).lower()
    provenance_verified = action.metadata.get("provenance_verified")
    manifest_hash_match = action.metadata.get("manifest_hash_match")
    if provenance_policy.get("block_manifest_hash_mismatch", True) and manifest_hash_match is False:
        matched.append("TK-PROVENANCE-HASH-001")
        return Decision.BLOCK, ["Tool or skill manifest integrity check failed."], None, matched
    if action.tool == "mcp_tool" or source_kind == "mcp":
        if mcp_policy.get("require_registered_server", False) and action.metadata.get("mcp_registered") is False:
            matched.append("TK-MCP-REGISTRY-001")
            return Decision.BLOCK, ["MCP server is not registered in the workspace trust registry."], None, matched
        if mcp_policy.get("require_verified_provenance", True) and provenance_verified is not True:
            matched.append("TK-MCP-PROVENANCE-001")
            return Decision.BLOCK, ["MCP tool provenance is not verified."], None, matched
        if mcp_policy.get("require_scope_subset", True) and action.metadata.get("scope_valid") is False:
            matched.append("TK-MCP-SCOPE-001")
            return Decision.BLOCK, ["Requested MCP scopes exceed the server registry allowlist."], None, matched
        if mcp_policy.get("block_token_passthrough", True) and action.metadata.get("token_passthrough") is True:
            matched.append("TK-MCP-TOKEN-PASSTHROUGH-001")
            return Decision.BLOCK, ["MCP token passthrough is forbidden; credentials must remain audience-bound."], None, matched
        if mcp_policy.get("require_audience_bound_token", True) and action.metadata.get("token_audience_valid") is False:
            matched.append("TK-MCP-AUDIENCE-001")
            return Decision.BLOCK, ["MCP access token is not bound to the intended resource audience."], None, matched
    if source_kind in {"skill", "plugin", "external_tool"} and provenance_policy.get("require_verified_external_tools", True):
        if provenance_verified is not True and op in {"exec", "install", "send", "post", "upload", "call", "write"}:
            matched.append("TK-TOOL-PROVENANCE-001")
            return Decision.BLOCK, ["External tool/skill provenance is unverified for a consequential action."], None, matched

    db_policy = policy.get("database", {})
    destructive = set(db_policy.get("destructive_operations", ["drop", "truncate", "delete", "alter"]))
    if action.tool == "database" and op in destructive:
        explicit = any(word in intent.user_request.lower() for word in ["delete", "drop", "truncate", "alter", "remove records"])
        if not explicit:
            matched.append("TK-DB-DESTRUCTIVE-001")
            reasons.append("Destructive database operation is not authorized by the user's intent.")
            if db_policy.get("repair_to_read_only", True):
                rewritten, repair_reasons = repair_action(action, "DB_DESTRUCTIVE")
                if rewritten is not None:
                    if agent is None or rewritten.operation in set(agent.allowed_operations.get("database", [])):
                        return Decision.REWRITE, reasons + repair_reasons, rewritten, matched
            return Decision.BLOCK, reasons, None, matched

    if agent is not None:
        allowed_ops = set(agent.allowed_operations.get(action.tool, []))
        if identity_policy.get("enforce_operation_allowlist") and allowed_ops and op not in allowed_ops:
            matched.append("TK-IAM-OP-001")
            return Decision.BLOCK, [f"Agent '{agent.id}' is not authorized for {action.tool}.{op}."], None, matched

    egress_policy = policy.get("egress", {})
    trusted_domains = set(intent.constraints.get("trusted_domains", []))
    if agent is not None:
        trusted_domains.update(agent.allowed_domains)

    if egress_policy.get("block_secret_to_untrusted", True) and "SECRET_DATA" in action_taints and op in EXTERNAL_SINKS:
        if action.destination and not _domain_trusted(action.destination, trusted_domains):
            matched.append("TK-DLP-SECRET-001")
            repaired, repair_reasons = repair_action(action, "SECRET_EGRESS")
            if repaired is not None and action.metadata.get("allow_redaction_repair", False):
                return Decision.REWRITE, ["Secret data would flow to an untrusted destination."] + repair_reasons, repaired, matched
            return Decision.BLOCK, ["Secret data would flow to an untrusted external destination."], None, matched

    memory_policy = policy.get("memory", {})
    if action.tool == "memory" and op == "write":
        if memory_policy.get("block_untrusted_write", True) and "UNTRUSTED_INPUT" in action_taints:
            matched.append("TK-MEMORY-POISON-001")
            return Decision.BLOCK, ["Untrusted content cannot be persisted into long-term agent memory."], None, matched
        if memory_policy.get("require_provenance_for_external_memory", True) and action.metadata.get("external_content") is True and action.metadata.get("provenance_verified") is not True:
            matched.append("TK-MEMORY-PROVENANCE-001")
            return Decision.BLOCK, ["External content cannot enter durable memory without verified provenance."], None, matched

    inter_agent_policy = policy.get("inter_agent", {})
    if action.tool == "agent_message" and op == "send":
        claimed_sender = action.metadata.get("claimed_sender")
        if inter_agent_policy.get("block_spoofed_sender", True) and claimed_sender and agent is not None and claimed_sender != agent.id:
            matched.append("TK-A2A-SPOOF-001")
            return Decision.BLOCK, [f"Inter-agent message claims sender '{claimed_sender}' but authenticated identity is '{agent.id}'."], None, matched
        recipient = action.resource
        if inter_agent_policy.get("require_fresh_nonce", True) and action.metadata.get("replay_detected") is True:
            matched.append("TK-A2A-REPLAY-001")
            return Decision.BLOCK, ["Inter-agent message nonce was already seen; replay attempt blocked."], None, matched
        if inter_agent_policy.get("require_fresh_nonce", True) and action.metadata.get("message_fresh") is False:
            matched.append("TK-A2A-STALE-001")
            return Decision.BLOCK, ["Inter-agent message timestamp is outside the accepted freshness window."], None, matched
        if inter_agent_policy.get("require_valid_signature", True) and action.metadata.get("signature_valid") is False:
            matched.append("TK-A2A-SIGNATURE-001")
            return Decision.BLOCK, ["Inter-agent message signature or authenticity proof is invalid."], None, matched
        if inter_agent_policy.get("require_registered_recipient", True) and action.metadata.get("recipient_registered") is False:
            matched.append("TK-A2A-RECIPIENT-001")
            return Decision.BLOCK, [f"Inter-agent recipient '{recipient}' is not a registered trusted agent."], None, matched

    workflow_policy = policy.get("workflow", {})
    if action.tool == "workflow" and op == "trigger":
        fanout = int(action.metadata.get("fanout", 1))
        hard = int(workflow_policy.get("hard_block_fanout", 50))
        automatic = int(workflow_policy.get("max_autonomous_fanout", 10))
        if fanout >= hard:
            matched.append("TK-CASCADE-BLOCK-001")
            return Decision.BLOCK, [f"Workflow fan-out {fanout} exceeds hard safety limit {hard}."], None, matched
        if fanout > automatic:
            matched.append("TK-CASCADE-APPROVAL-001")
            return Decision.REQUIRE_APPROVAL, [f"Workflow fan-out {fanout} exceeds autonomous limit {automatic}."], None, matched

    payment_policy = policy.get("payments", {})
    if action.tool == "payment" and action.amount is not None:
        configured = float(intent.constraints.get("payment_auto_limit", payment_policy.get("default_auto_limit", 50000)))
        if agent is not None and agent.max_payment is not None:
            configured = min(configured, float(agent.max_payment))
        if action.amount > configured:
            matched.append("TK-PAYMENT-APPROVAL-001")
            return Decision.REQUIRE_APPROVAL, [f"Payment amount {action.amount:.0f} exceeds agent automatic limit {configured:.0f}."], None, matched

    github_policy = policy.get("github", {})
    protected = set(github_policy.get("protected_branches", ["main", "master"]))
    if action.tool == "github" and op == "push" and action.resource in protected:
        matched.append("TK-GIT-PROTECTED-001")
        repaired, repair_reasons = repair_action(action, "PROTECTED_BRANCH")
        if repaired is not None:
            return Decision.REWRITE, ["Direct push to a protected branch is not allowed."] + repair_reasons, repaired, matched
        return Decision.REQUIRE_APPROVAL, ["Push to a protected branch requires approval."], None, matched

    if egress_policy.get("approval_for_untrusted_influence", True) and "UNTRUSTED_INPUT" in action_taints and op in EXTERNAL_SINKS:
        matched.append("TK-UNTRUSTED-SIDE-EFFECT-001")
        return Decision.REQUIRE_APPROVAL, ["A side-effecting action is causally influenced by untrusted input."], None, matched

    matched.append("TK-DEFAULT-AUDIT-001")
    return Decision.ALLOW_WITH_LOG, ["No restrictive policy matched; action is permitted and audited."], None, matched
