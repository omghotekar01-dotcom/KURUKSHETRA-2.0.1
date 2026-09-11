from __future__ import annotations
from typing import List
from ..models import Action, Decision


DECISION_BASE = {
    Decision.ALLOW: 5,
    Decision.ALLOW_WITH_LOG: 12,
    Decision.REWRITE: 48,
    Decision.REQUIRE_APPROVAL: 72,
    Decision.BLOCK: 92,
}


def action_risk(action: Action, decision: Decision) -> int:
    score = DECISION_BASE[decision]
    if action.source_trust.value == "UNTRUSTED":
        score += 10
    if action.sensitivity.value == "CONFIDENTIAL":
        score += 8
    if action.sensitivity.value == "SECRET":
        score += 16
    if action.destination:
        score += 5
    if action.tool == "payment" and (action.amount or 0) > 50000:
        score += 10
    return max(0, min(100, score))


def aggregate_risk(scores: List[int]) -> int:
    if not scores:
        return 0
    peak = max(scores)
    avg = sum(scores) / len(scores)
    return int(round(min(100, peak * 0.75 + avg * 0.25)))
