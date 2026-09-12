from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, Mapping, Sequence

_WRAPPERS = ("results", "records", "runs", "cases", "evaluations")


def _text(value: Any, default: str = "unspecified") -> str:
    text = str(value).strip() if value is not None else ""
    return text or default


def _boolean(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "pass", "passed", "success", "1"}:
            return True
        if normalized in {"false", "fail", "failed", "failure", "0"}:
            return False
    return None


def _digest(rows: Sequence[Mapping[str, Any]]) -> str:
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _rate(values: Iterable[bool | None]) -> float | None:
    usable = [value for value in values if value is not None]
    if not usable:
        return None
    return round(sum(1 for value in usable if value) / len(usable), 4)


def _extract_rows(payload: Any) -> tuple[list[Any], Dict[str, Any]]:
    if isinstance(payload, Mapping):
        for key in _WRAPPERS:
            value = payload.get(key)
            if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                metadata = {k: v for k, v in payload.items() if k != key}
                return list(value), metadata
        return [payload], {}
    if isinstance(payload, Sequence) and not isinstance(payload, (str, bytes, bytearray)):
        return list(payload), {}
    raise ValueError("AgentDojo payload must be an object or list of result objects")


def import_agentdojo_results(payload: Any) -> Dict[str, Any]:
    """Normalize upstream AgentDojo result records without changing score semantics.

    `utility` and `security` are treated as upstream validator outputs. TrustKernel
    deliberately does not reinterpret `security=True` as attack success, attack
    resistance, or a TrustKernel block-rate because AgentDojo scoring semantics and
    edge-case handling can vary across releases. Consumers should retain the recorded
    upstream version/commit and use the upstream implementation to reproduce scores.
    """

    raw_rows, wrapper_metadata = _extract_rows(payload)
    rows: list[Dict[str, Any]] = []
    errors: list[Dict[str, Any]] = []

    for index, item in enumerate(raw_rows):
        if not isinstance(item, Mapping):
            errors.append({"index": index, "error": "result must be an object"})
            continue

        user_task_id = item.get("user_task_id", item.get("user_task"))
        injection_task_id = item.get("injection_task_id", item.get("injection_task"))
        suite = item.get("suite", item.get("suite_name", wrapper_metadata.get("suite", "unspecified")))
        utility = _boolean(item.get("utility", item.get("utility_success", item.get("user_task_success"))))
        security = _boolean(item.get("security", item.get("security_success")))

        if user_task_id in (None, ""):
            errors.append({"index": index, "error": "missing user_task_id"})
            continue
        if utility is None and security is None:
            errors.append({"index": index, "user_task_id": str(user_task_id), "error": "missing utility/security validator outputs"})
            continue

        rows.append({
            "suite": _text(suite),
            "user_task_id": _text(user_task_id),
            "injection_task_id": None if injection_task_id in (None, "") else str(injection_task_id),
            "attack": _text(item.get("attack", item.get("attack_name", wrapper_metadata.get("attack", "none"))), "none"),
            "defense": _text(item.get("defense", item.get("defense_name", wrapper_metadata.get("defense", "none"))), "none"),
            "model": _text(item.get("model", item.get("model_name", wrapper_metadata.get("model", "unspecified")))),
            "utility": utility,
            "security": security,
            "trace_ref": item.get("trace_ref", item.get("trace_path", item.get("trajectory_ref"))),
            "source_index": index,
        })

    return {
        "schema": "trustkernel.agentdojo-import.v1",
        "source": "AgentDojo upstream validator outputs",
        "semantic_policy": "pass-through",
        "warning": (
            "Utility/security values are preserved upstream validator outputs only. "
            "They are not TrustKernel production security accuracy, certification, or guaranteed real-world protection."
        ),
        "wrapper_metadata": wrapper_metadata,
        "imported": len(rows),
        "rejected": len(errors),
        "errors": errors,
        "sha256": _digest(rows),
        "rows": rows,
    }


def build_agentdojo_report(payload: Any) -> Dict[str, Any]:
    imported = import_agentdojo_results(payload)
    rows = imported["rows"]

    grouped: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for dimension in ("suite", "attack", "defense", "model"):
        buckets: dict[str, list[Dict[str, Any]]] = defaultdict(list)
        for row in rows:
            buckets[str(row[dimension])].append(row)
        grouped[dimension] = {
            name: {
                "cases": len(bucket),
                "utility_true_rate": _rate(row["utility"] for row in bucket),
                "security_true_rate": _rate(row["security"] for row in bucket),
            }
            for name, bucket in sorted(buckets.items())
        }

    return {
        "schema": "trustkernel.agentdojo-report.v1",
        "warning": imported["warning"],
        "semantic_policy": imported["semantic_policy"],
        "dataset": {key: value for key, value in imported.items() if key != "rows"},
        "summary": {
            "cases": len(rows),
            "utility_scored": sum(row["utility"] is not None for row in rows),
            "security_scored": sum(row["security"] is not None for row in rows),
            "utility_true_rate": _rate(row["utility"] for row in rows),
            "security_true_rate": _rate(row["security"] for row in rows),
            "suites": dict(sorted(Counter(row["suite"] for row in rows).items())),
        },
        "grouped": grouped,
        "rows": rows,
        "claims_boundary": {
            "native_metrics_recomputed": False,
            "trustkernel_runtime_accuracy_claimed": False,
            "production_security_claimed": False,
            "note": "Reproduce native metrics with the recorded AgentDojo release and upstream task validators.",
        },
    }
