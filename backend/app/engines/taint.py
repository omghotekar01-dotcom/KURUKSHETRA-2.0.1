from __future__ import annotations
from typing import Dict, List, Set
from ..models import Action, Sensitivity, TrustLevel


class TaintState:
    """Tracks confidentiality/integrity labels per action and propagates along dependencies."""

    def __init__(self) -> None:
        self.labels: Set[str] = set()
        self.sources: List[str] = []
        self.by_action: Dict[str, Set[str]] = {}

    def observe(self, action: Action) -> Set[str]:
        labels: Set[str] = set(action.data_labels)
        if action.source_trust == TrustLevel.UNTRUSTED:
            labels.add("UNTRUSTED_INPUT")
            self.sources.append(action.id)
        if action.sensitivity == Sensitivity.SECRET:
            labels.add("SECRET_DATA")
            self.sources.append(action.id)
        elif action.sensitivity == Sensitivity.CONFIDENTIAL:
            labels.add("CONFIDENTIAL_DATA")
            self.sources.append(action.id)
        elif action.sensitivity == Sensitivity.INTERNAL:
            labels.add("INTERNAL_DATA")

        resource = action.resource.lower()
        if any(token in resource for token in [".env", "secret", "credential", "token", "api_key", "private_key"]):
            labels.add("SECRET_DATA")
            self.sources.append(action.id)

        for dependency in action.depends_on:
            labels.update(self.by_action.get(dependency, set()))

        # Deterministic sanitizers are allowed to remove specific propagated labels.
        for sanitized in action.metadata.get("sanitizes", []):
            labels.discard(str(sanitized))

        self.by_action[action.id] = set(labels)
        self.labels.update(labels)
        return labels

    def labels_for(self, action_id: str) -> Set[str]:
        return set(self.by_action.get(action_id, set()))

    def snapshot(self) -> Dict[str, object]:
        return {
            "labels": sorted(self.labels),
            "sources": list(dict.fromkeys(self.sources)),
            "by_action": {key: sorted(value) for key, value in self.by_action.items()},
        }
