from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from statistics import mean
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from pydantic import ValidationError

from ..engines.kernel import evaluate_plan
from ..models import PlanRequest


_ATTACK_STOP_DECISIONS = {"BLOCK", "REQUIRE_APPROVAL"}
_BENIGN_SUCCESS_DECISIONS = {"ALLOW", "ALLOW_WITH_LOG", "REWRITE"}
_SUPPORTED_WRAPPER_KEYS = ("cases", "results", "tasks")


def _normalise_kind(case: Mapping[str, Any]) -> str:
    raw = case.get("kind", case.get("case_type", case.get("security_label", "unspecified")))
    value = str(raw).strip().lower().replace("_", "-")
    aliases = {
        "security": "attack",
        "malicious": "attack",
        "injection": "attack",
        "prompt-injection": "attack",
        "utility": "benign",
        "safe": "benign",
        "clean": "benign",
    }
    return aliases.get(value, value)


def _dataset_digest(cases: Sequence[Mapping[str, Any]]) -> str:
    canonical = json.dumps(cases, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


class BenchmarkAdapter:
    """Import and evaluate TrustKernel/AgentDojo-style security cases.

    The importer deliberately uses a small provider-neutral interchange shape instead
    of pretending to be a drop-in parser for every upstream AgentDojo release.
    Canonical case fields are:

      - id/task_id: stable case identity
      - kind/case_type/security_label: attack | benign | approval | ambiguous
      - plan: TrustKernel PlanRequest-compatible action plan
      - expected_decisions: optional acceptable TrustKernel decisions
      - suite, attack, defense, source: optional provenance dimensions

    Payloads may be a list of cases or a mapping containing `cases`, `results`, or
    `tasks`. The report keeps security and utility metrics separate and always labels
    imported benchmark output as evaluation evidence rather than production accuracy.
    """

    def import_payload(
        self,
        payload: Any,
        *,
        source: str = "external",
        suite: str | None = None,
        dataset_version: str | None = None,
    ) -> Dict[str, Any]:
        if isinstance(payload, Mapping):
            raw_cases = None
            wrapper_key = None
            for key in _SUPPORTED_WRAPPER_KEYS:
                if key in payload:
                    raw_cases = payload[key]
                    wrapper_key = key
                    break
            if raw_cases is None:
                raw_cases = [payload]
                wrapper_key = "single"
            source = str(payload.get("source", source))
            suite = str(payload.get("suite", suite)) if payload.get("suite", suite) is not None else None
            dataset_version = (
                str(payload.get("dataset_version", dataset_version))
                if payload.get("dataset_version", dataset_version) is not None
                else None
            )
        elif isinstance(payload, Sequence) and not isinstance(payload, (str, bytes, bytearray)):
            raw_cases = payload
            wrapper_key = "list"
        else:
            raise ValueError("benchmark payload must be a case list or mapping")

        if not isinstance(raw_cases, Sequence) or isinstance(raw_cases, (str, bytes, bytearray)):
            raise ValueError("benchmark case collection must be a list")

        cases: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []
        seen_ids: set[str] = set()
        for index, item in enumerate(raw_cases):
            if not isinstance(item, Mapping):
                errors.append({"index": index, "error": "case must be an object"})
                continue
            case = dict(item)
            case_id = str(case.get("id", case.get("task_id", f"case-{index + 1}")))
            if case_id in seen_ids:
                errors.append({"index": index, "id": case_id, "error": "duplicate case id"})
                continue
            seen_ids.add(case_id)
            plan = case.get("plan", case.get("request"))
            if plan is None:
                errors.append({"index": index, "id": case_id, "error": "missing plan/request"})
                continue
            expected = case.get("expected_decisions", case.get("expected", []))
            if isinstance(expected, str):
                expected = [expected]
            if not isinstance(expected, Sequence):
                errors.append({"index": index, "id": case_id, "error": "expected_decisions must be a list"})
                continue
            cases.append({
                **case,
                "id": case_id,
                "kind": _normalise_kind(case),
                "plan": plan,
                "expected_decisions": [str(value) for value in expected],
                "source": str(case.get("source", source)),
                "suite": str(case.get("suite", suite or "unspecified")),
                "attack": str(case.get("attack", case.get("attack_name", "none"))),
                "defense": str(case.get("defense", case.get("defense_name", "trustkernel"))),
            })

        return {
            "schema": "trustkernel.benchmark.dataset.v1",
            "source": source,
            "suite": suite,
            "dataset_version": dataset_version,
            "wrapper": wrapper_key,
            "imported": len(cases),
            "rejected": len(errors),
            "errors": errors,
            "sha256": _dataset_digest(cases),
            "cases": cases,
        }

    def run_payload(
        self,
        payload: Any,
        *,
        workspace_id: str | None = None,
        source: str = "external",
        suite: str | None = None,
        dataset_version: str | None = None,
    ) -> Dict[str, Any]:
        dataset = self.import_payload(
            payload,
            source=source,
            suite=suite,
            dataset_version=dataset_version,
        )
        report = self.run_cases(dataset["cases"], workspace_id=workspace_id)
        report["dataset"] = {key: value for key, value in dataset.items() if key != "cases"}
        return report

    def run_cases(self, cases: Iterable[Dict[str, Any]], workspace_id: str | None = None) -> Dict[str, Any]:
        rows: List[Dict[str, Any]] = []
        for index, case in enumerate(cases):
            case_id = str(case.get("id", case.get("task_id", f"case-{index + 1}")))
            kind = _normalise_kind(case)
            expected = {str(item) for item in case.get("expected_decisions", [])}
            dimensions = {
                "source": str(case.get("source", "unspecified")),
                "suite": str(case.get("suite", "unspecified")),
                "attack": str(case.get("attack", case.get("attack_name", "none"))),
                "defense": str(case.get("defense", case.get("defense_name", "trustkernel"))),
            }
            try:
                request = PlanRequest.model_validate(case["plan"])
                result = evaluate_plan(request, workspace_id=workspace_id)
                decision = result.decision.value
                rows.append({
                    "id": case_id,
                    "kind": kind,
                    **dimensions,
                    "decision": decision,
                    "expected_decisions": sorted(expected),
                    "correct": not expected or decision in expected,
                    "risk_score": result.risk_score,
                    "latency_ms": result.metrics.get("evaluation_latency_ms"),
                    "audit_id": result.audit_id,
                    "attack_blocked": kind == "attack" and decision in _ATTACK_STOP_DECISIONS,
                    "benign_completed": kind == "benign" and decision in _BENIGN_SUCCESS_DECISIONS,
                })
            except (KeyError, ValidationError, TypeError, ValueError) as exc:
                rows.append({"id": case_id, "kind": kind, **dimensions, "error": str(exc), "correct": False})

        valid_rows = [row for row in rows if "decision" in row]
        attack_rows = [row for row in valid_rows if row.get("kind") == "attack"]
        benign_rows = [row for row in valid_rows if row.get("kind") == "benign"]
        latencies = [float(row["latency_ms"]) for row in valid_rows if row.get("latency_ms") is not None]
        decisions = Counter(row["decision"] for row in valid_rows)

        attack_block_rate = _rate(sum(bool(row.get("attack_blocked")) for row in attack_rows), len(attack_rows))
        benign_completion_rate = _rate(sum(bool(row.get("benign_completed")) for row in benign_rows), len(benign_rows))
        false_negative_rate = round(1 - attack_block_rate, 4) if attack_block_rate is not None else None
        false_positive_rate = _rate(
            sum(row["decision"] in _ATTACK_STOP_DECISIONS for row in benign_rows),
            len(benign_rows),
        )

        grouped: Dict[str, Dict[str, Dict[str, Any]]] = {}
        for dimension in ("source", "suite", "attack", "defense"):
            buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for row in valid_rows:
                buckets[str(row.get(dimension, "unspecified"))].append(row)
            grouped[dimension] = {}
            for name, bucket in sorted(buckets.items()):
                attacks = [row for row in bucket if row.get("kind") == "attack"]
                benign = [row for row in bucket if row.get("kind") == "benign"]
                grouped[dimension][name] = {
                    "cases": len(bucket),
                    "attack_cases": len(attacks),
                    "attack_block_rate": _rate(sum(bool(row.get("attack_blocked")) for row in attacks), len(attacks)),
                    "benign_cases": len(benign),
                    "benign_completion_rate": _rate(sum(bool(row.get("benign_completed")) for row in benign), len(benign)),
                    "expected_outcome_rate": _rate(sum(bool(row.get("correct")) for row in bucket), len(bucket)),
                }

        return {
            "schema": "trustkernel.benchmark.v3",
            "warning": (
                "Imported or synthetic benchmark results are regression/evaluation evidence only; "
                "they are not production security accuracy, certification, or a real-world guarantee."
            ),
            "cases": len(rows),
            "executed": len(valid_rows),
            "errors": len(rows) - len(valid_rows),
            "expected_outcome_rate": _rate(sum(bool(r.get("correct")) for r in rows), len(rows)),
            "security": {
                "attack_cases": len(attack_rows),
                "attack_block_rate": attack_block_rate,
                "false_negative_rate": false_negative_rate,
            },
            "utility": {
                "benign_cases": len(benign_rows),
                "benign_completion_rate": benign_completion_rate,
                "false_positive_rate": false_positive_rate,
            },
            "performance": {
                "mean_latency_ms": round(mean(latencies), 4) if latencies else None,
                "max_latency_ms": round(max(latencies), 4) if latencies else None,
            },
            "decision_counts": dict(sorted(decisions.items())),
            "breakdown": grouped,
            "rows": rows,
        }


benchmark_adapter = BenchmarkAdapter()
