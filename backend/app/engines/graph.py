from __future__ import annotations
from typing import Dict, List, Any
from ..models import Action


def build_action_graph(actions: List[Action], taint_by_action: Dict[str, List[str]] | None = None) -> Dict[str, Any]:
    nodes = []
    edges = []
    ids = {a.id for a in actions}
    taint_by_action = taint_by_action or {}
    for action in actions:
        nodes.append({
            "id": action.id,
            "label": f"{action.tool}.{action.operation}",
            "resource": action.resource,
            "destination": action.destination,
            "sensitivity": action.sensitivity.value,
            "trust": action.source_trust.value,
            "labels": taint_by_action.get(action.id, []),
        })

    for i, action in enumerate(actions):
        dependencies = [dep for dep in action.depends_on if dep in ids]
        if dependencies:
            for dep in dependencies:
                edges.append({"from": dep, "to": action.id, "type": "data_dependency"})
        elif i > 0:
            edges.append({"from": actions[i - 1].id, "to": action.id, "type": "sequence"})
    return {"nodes": nodes, "edges": edges}


def graph_patterns(actions: List[Action], taint_by_action: Dict[str, set[str]] | None = None) -> List[Dict[str, Any]]:
    patterns: List[Dict[str, Any]] = []
    taint_by_action = taint_by_action or {}
    external_ops = {"send", "post", "upload", "publish", "push"}
    for action in actions:
        labels = taint_by_action.get(action.id, set())
        if action.operation.lower() in external_ops and action.destination:
            if "SECRET_DATA" in labels or "CONFIDENTIAL_DATA" in labels:
                patterns.append({
                    "type": "sensitive_to_external_sink",
                    "source": action.depends_on[0] if action.depends_on else action.id,
                    "sink": action.id,
                    "resource": action.resource or "derived sensitive data",
                    "destination": action.destination,
                    "labels": sorted(labels),
                })
            if "UNTRUSTED_INPUT" in labels and action.operation.lower() in external_ops:
                patterns.append({
                    "type": "untrusted_influence_to_side_effect",
                    "source": action.depends_on[0] if action.depends_on else action.id,
                    "sink": action.id,
                    "destination": action.destination,
                    "labels": sorted(labels),
                })
    return patterns
