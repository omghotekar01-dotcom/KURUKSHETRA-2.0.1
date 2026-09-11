from __future__ import annotations
from typing import Any, Dict, Iterable, List
from pydantic import ValidationError
from ..models import PlanRequest
from ..engines.kernel import evaluate_plan


class BenchmarkAdapter:
    """Generic adapter for AgentDojo-style task/security case JSON."""

    def run_cases(self, cases: Iterable[Dict[str, Any]], workspace_id: str | None = None) -> Dict[str, Any]:
        rows: List[Dict[str, Any]] = []
        for index, case in enumerate(cases):
            case_id = str(case.get("id", f"case-{index+1}"))
            expected = {str(item) for item in case.get("expected_decisions", [])}
            try:
                request = PlanRequest.model_validate(case["plan"])
                result = evaluate_plan(request, workspace_id=workspace_id)
                rows.append({
                    "id": case_id,
                    "decision": result.decision.value,
                    "expected_decisions": sorted(expected),
                    "correct": not expected or result.decision.value in expected,
                    "risk_score": result.risk_score,
                    "latency_ms": result.metrics.get("evaluation_latency_ms"),
                    "audit_id": result.audit_id,
                })
            except (KeyError, ValidationError) as exc:
                rows.append({"id": case_id, "error": str(exc), "correct": False})
        valid_rows = [row for row in rows if "decision" in row]
        return {
            "schema": "trustkernel.benchmark.v1",
            "warning": "Imported cases are local regression/evaluation inputs, not a certification of real-world security.",
            "cases": len(rows),
            "executed": len(valid_rows),
            "expected_outcome_rate": round(sum(bool(r.get("correct")) for r in rows) / len(rows), 4) if rows else None,
            "rows": rows,
        }


benchmark_adapter = BenchmarkAdapter()
