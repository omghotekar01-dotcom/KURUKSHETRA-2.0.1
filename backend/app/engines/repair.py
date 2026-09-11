from __future__ import annotations
from typing import Optional, Tuple, List
from ..models import Action, Sensitivity


def repair_action(action: Action, reason_code: str) -> Tuple[Optional[Action], List[str]]:
    """Returns a minimally changed safe alternative when one can be justified deterministically."""
    op = action.operation.lower()

    if reason_code == "DB_DESTRUCTIVE" and action.tool == "database":
        repaired = action.model_copy(update={
            "operation": "select",
            "metadata": {**action.metadata, "rewritten_from": op, "repair": "read_only_preview"},
        })
        return repaired, ["Replaced destructive database mutation with a read-only preview."]

    if reason_code == "SECRET_EGRESS" and op in {"send", "post", "upload", "publish"}:
        repaired = action.model_copy(update={
            "resource": "redacted_summary",
            "sensitivity": Sensitivity.PUBLIC,
            "data_labels": [label for label in action.data_labels if label not in {"SECRET_DATA", "CONFIDENTIAL_DATA"}],
            "metadata": {**action.metadata, "repair": "redact_sensitive_payload", "redacted": True, "sanitizes": ["SECRET_DATA", "CONFIDENTIAL_DATA"]},
        })
        return repaired, ["Replaced sensitive payload with a redacted summary before external egress."]

    if reason_code == "PROTECTED_BRANCH" and action.tool == "github" and op == "push":
        repaired = action.model_copy(update={
            "resource": f"trustkernel/{action.resource or 'safe-change'}",
            "metadata": {**action.metadata, "repair": "push_to_feature_branch"},
        })
        return repaired, ["Redirected push from protected branch to an isolated feature branch."]

    return None, []
