from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Decision(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_WITH_LOG = "ALLOW_WITH_LOG"
    REWRITE = "REWRITE"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"


class Sensitivity(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"


class TrustLevel(str, Enum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    UNKNOWN = "UNKNOWN"


class Intent(BaseModel):
    user_request: str
    allowed_tools: List[str] = Field(default_factory=list)
    constraints: Dict[str, Any] = Field(default_factory=dict)


class AgentIdentity(BaseModel):
    id: str
    name: str
    owner: str = "demo-org"
    workspace_id: Optional[str] = None
    allowed_tools: List[str] = Field(default_factory=list)
    allowed_operations: Dict[str, List[str]] = Field(default_factory=dict)
    allowed_domains: List[str] = Field(default_factory=list)
    max_payment: Optional[float] = None
    environment: str = "demo"
    tags: List[str] = Field(default_factory=list)


class Action(BaseModel):
    id: str
    tool: str
    operation: str
    resource: str = ""
    destination: str = ""
    amount: Optional[float] = None
    source_trust: TrustLevel = TrustLevel.UNKNOWN
    sensitivity: Sensitivity = Sensitivity.PUBLIC
    depends_on: List[str] = Field(default_factory=list)
    data_labels: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PlanRequest(BaseModel):
    intent: Intent
    actions: List[Action]
    policy_profile: str = "enterprise-default"
    agent_id: Optional[str] = None


class GatewayRequest(BaseModel):
    agent_id: str
    intent: Intent
    action: Action
    policy_profile: str = "enterprise-default"


class Finding(BaseModel):
    code: str
    severity: str
    title: str
    detail: str
    action_ids: List[str] = Field(default_factory=list)
    policy_id: Optional[str] = None


class ActionResult(BaseModel):
    action: Action
    decision: Decision
    risk: int
    reasons: List[str] = Field(default_factory=list)
    rewritten_action: Optional[Action] = None
    matched_policies: List[str] = Field(default_factory=list)


class EvaluationResult(BaseModel):
    decision: Decision
    risk_score: int
    summary: str
    findings: List[Finding]
    action_results: List[ActionResult]
    graph: Dict[str, Any]
    audit_id: str
    approval_required: bool = False
    metrics: Dict[str, Any] = Field(default_factory=dict)
