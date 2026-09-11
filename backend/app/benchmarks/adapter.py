from __future__ import annotations
from collections import Counter
from statistics import mean
from typing import Any, Dict, Iterable, List

from pydantic import ValidationError

from ..engines.kernel import evaluate_plan
from ..models import PlanRequest


_ATTACK_STOP_DECISIONS = {"BLOCK", "REQUIRE_APPROVAL"}
_BENIGN_SUCCESS_DECISIONS = {"ALLOW", "ALLOW_WITH_LOG", "REWRITE"}


class BenchmarkAdapter:
    """Generic adapter for AgentDojo-style task/security case JSON.

    Supported optional case fields:
      - kind: attack | benign | approval | ambiguous
      - expected_decisions: list of acceptable TrustKernel decisions
      - attack_should_succeed: normally false for security cases

    This keeps security and usefulness visible at the same time instead of
    reporting one flattering aggregate number.
    """

    def run_cases(self, cases: Iterable[Dict[str, Any]], workspace_id: str | None = None) -> Dict[str, Any]:
        rows: List[Dict[str, Any]] = []
        for index, case in enumerate(cases):
            case_id = str(case.get("id", f"case-{index+1}"))
            kind = str(case.get("kind", "unspecified")).lower()
            expected = {str(item) for item in case.get("expected_decisions", [])}
            try:
                request = PlanRequest.model_validate(case["plan"])
                result = evaluate_plan(request, workspace_id=workspace_id)
                decision = result.decision.value
                rows.append({
                    "id": case_id,
                    "kind": kind,
                    "decision": decision,
                    "expected_decisions": sorted(expected),
                    "correct": not expected or decision in expected,
                    "risk_score": result.risk_score,
                    "latency_ms": result.metrics.get("evaluation_latency_ms"),
                    "audit_id": result.audit_id,
                    "attack_blocked": kind == "attack" and decision in _ATTACK_STOP_DECISIONS,
                    "benign_completed": kind == "benign" and decision in _BENIGN_SUCCESS_DECISIONS,
                })
            except (KeyError, ValidationError) as exc:
                rows.append({"id": case_id, "kind": kind, "error": str(exc), "correct": False})

        valid_rows = [row for row in rows if "decision" in row]
        attack_rows = [row for row in valid_rows if row.get("kind") == "attack"]
        benign_rows = [row for row in valid_rows if row.get("kind") == "benign"]
        latencies = [float(row["latency_ms"]) for row in valid_rows if row.get("latency_ms") is not None]
        decisions = Counter(row["decision"] for row in valid_rows)

        attack_block_rate = (
            sum(bool(row.get("attack_blocked")) for row in attack_rows) / len(attack_rows)
            if attack_rows else None
        )
        benign_completion_rate = (
            sum(bool(row.get("benign_completed")) for row in benign_rows) / len(benign_rows)
            if benign_rows else None
        )
        false_negative_rate = (1 - attack_block_rate) if attack_block_rate is not None else None
        false_positive_rate = (
            sum(row["decision"] in _ATTACK_STOP_DECISIONS for row in benign_rows) / len(benign_rows)
            if benign_rows else None
        )

        return {
            "schema": "trustkernel.benchmark.v2",
            "warning": "Imported cases are regression/evaluation inputs, not a certification of real-world security.",
            "cases": len(rows),
            "executed": len(valid_rows),
            "expected_outcome_rate": round(sum(bool(r.get("correct")) for r in rows) / len(rows), 4) if rows else None,
            "security": {
                "attack_cases": len(attack_rows),
                "attack_block_rate": round(attack_block_rate, 4) if attack_block_rate is not None else None,
                "false_negative_rate": round(false_negative_rate, 4) if false_negative_rate is not None else None,
            },
            "utility": {
                "benign_cases": len(benign_rows),
                "benign_completion_rate": round(benign_completion_rate, 4) if benign_completion_rate is not None else None,
                "false_positive_rate": round(false_positive_rate, 4) if false_positive_rate is not None else None,
            },
            "performance": {
                "mean_latency_ms": round(mean(latencies), 4) if latencies else None,
                "max_latency_ms": round(max(latencies), 4) if latencies else None,
            },
            "decision_counts": dict(sorted(decisions.items())),
            "rows": rows,
        }


benchmark_adapter = BenchmarkAdapter()
