from __future__ import annotations
from typing import Dict, Any
from ..models import Action


def simulate(action: Action) -> Dict[str, Any]:
    op = action.operation.lower()
    if action.tool == "database" and op in {"drop", "truncate", "delete"}:
        return {"impact": "high", "reversible": False, "predicted": "Potential destructive database mutation"}
    if action.tool == "payment":
        return {"impact": "financial", "reversible": False, "predicted": f"Would transfer simulated amount {action.amount or 0:.0f}"}
    if op in {"send", "post", "upload", "publish"}:
        return {"impact": "egress", "reversible": False, "predicted": f"Would send data to {action.destination or 'external sink'}"}
    return {"impact": "low", "reversible": True, "predicted": "No irreversible effect predicted"}
