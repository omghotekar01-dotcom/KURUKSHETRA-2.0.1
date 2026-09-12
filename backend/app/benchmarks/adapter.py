from __future__ import annotations

import hashlib
import json
import math
from collections import Counter, defaultdict
from statistics import mean
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from pydantic import ValidationError

from ..engines.kernel import evaluate_plan
from ..models import PlanRequest


_ATTACK_STOP_DECISIONS = {"BLOCK", "REQUIRE_APPROVAL"}
_BENIGN_SUCCESS_DECISIONS = {"ALLOW", "ALLOW_WITH_LOG", "REWRITE"}
_SUPPORTED_WRAPPER_KEYS = ("cases", "results", "tasks", "runs", "records")
_PROVENANCE_DIMENSIONS = ("source", "suite", "attack", "defense", "model")


def _normalise_text(value: Any, default: str) -> str:
    text = str(value).strip() if value is not None else ""
    return text or default


def _normalise_kind(case: Mapping[str, Any]) -> str:
    raw = case.get("kind", case.get("case_type", case.get("security_label")))
    if raw is None:
        injection_task = case.get("injection_task_id", case.get("injection_task"))
        attack = _normalise_text(case.get("attack", case.get("attack_name")), "none").lower()
        raw = "attack" if injection_task not in (None, "", "none") or attack not in {"none", "null", "benign"} else "unspecified"
    value = str(raw).strip().lower().replace("_", "-")
    aliases = {
        "security": "attack",
        "malicious": "attack",
        "injection": "attack",
        "prompt-injection": "attack",
        "adversarial": "attack",
        "utility": "benign",
        "safe": "benign",
        "clean": "benign",
        "legitimate": "benign",
    }
    return aliases.get(value, value)


def _dataset_digest(cases: Sequence[Mapping[str, Any]]) -> str:
    canonical = json.dumps(cases, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _wilson(successes: int, total: int, z: float = 1.96) -> Dict[str, float] | None:
    """Return a 95% Wilson interval for a binomial proportion.

    The interval communicates sample-size uncertainty without implying that a
    benchmark sample estimates production security accuracy.
    """
    if total <= 0:
        return None
    p = successes / total
    denominator = 1 + (z * z / total)
    centre = (p + (z * z / (2 * total))) / denominator
    margin = (z / denominator) * math.sqrt((p * (1 - p) / total) + (z * z / (4 * total * total)))
    return {"low": round(max(0.0, centre - margin), 4), "high": round(min(1.0, centre + margin), 4)}


def _unique(rows: Sequence[Mapping[str, Any]], key: str) -> List[str]:
    return sorted({str(row.get(key, "unspecified")) for row in rows})


class BenchmarkAdapter:
    """Import and evaluate TrustKernel/AgentDojo-inspired security cases.

    TrustKernel intentionally uses a provider-neutral interchange format. The
    adapter preserves common AgentDojo-style provenance dimensions (suite,
    user task, injection task, attack, defense, model and trace reference), but
    it does not claim byte-for-byte compatibility with every upstream release.
    Native AgentDojo utility/targeted-ASR semantics require the upstream task
    environment and are therefore never inferred from TrustKernel decisions.
    """

    def import_payload(
        self,
        payload: Any,
        *,
        source: str = "external",
        suite: str | None = None,
        dataset_version: str | None = None,
    ) -> Dict[str, Any]:
        wrapper_metadata: Dict[str, Any] = {}
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
            source = _normalise_text(payload.get("source", source), source)
            suite_value = payload.get("suite", suite)
            suite = str(suite_value) if suite_value is not None else None
            version_value = payload.get("dataset_version", payload.get("version", dataset_version))
            dataset_version = str(version_value) if version_value is not None else None
            wrapper_metadata = {
                key: payload[key]
                for key in ("model", "model_name", "attack", "attack_name", "defense", "defense_name", "run_id", "commit")
                if key in payload
            }
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
            case_id = _normalise_text(case.get("id", case.get("task_id", case.get("case_id"))), f"case-{index + 1}")
            if case_id in seen_ids:
                errors.append({"index": index, "id": case_id, "error": "duplicate case id"})
                continue
            seen_ids.add(case_id)

            plan = case.get("plan", case.get("request"))
            if plan is None:
                errors.append({"index": index, "id": case_id, "error": "missing plan/request"})
                continue
            if not isinstance(plan, Mapping):
                errors.append({"index": index, "id": case_id, "error": "plan/request must be an object"})
                continue

            expected = case.get("expected_decisions", case.get("expected_decision", case.get("expected", [])))
            if isinstance(expected, str):
                expected = [expected]
            if not isinstance(expected, Sequence) or isinstance(expected, (str, bytes, bytearray)):
                errors.append({"index": index, "id": case_id, "error": "expected_decisions must be a list or string"})
                continue

            attack = case.get("attack", case.get("attack_name", wrapper_metadata.get("attack", wrapper_metadata.get("attack_name", "none"))))
            defense = case.get("defense", case.get("defense_name", wrapper_metadata.get("defense", wrapper_metadata.get("defense_name", "trustkernel"))))
            model = case.get("model", case.get("model_name", wrapper_metadata.get("model", wrapper_metadata.get("model_name", "unspecified"))))
            cases.append({
                **case,
                "id": case_id,
                "kind": _normalise_kind({**case, "attack": attack}),
                "plan": dict(plan),
                "expected_decisions": [str(value).upper() for value in expected],
                "source": _normalise_text(case.get("source", source), source),
                "suite": _normalise_text(case.get("suite", suite), "unspecified"),
                "attack": _normalise_text(attack, "none"),
                "defense": _normalise_text(defense, "trustkernel"),
                "model": _normalise_text(model, "unspecified"),
                "user_task_id": case.get("user_task_id", case.get("user_task")),
                "injection_task_id": case.get("injection_task_id", case.get("injection_task")),
                "trace_ref": case.get("trace_ref", case.get("trace_url", case.get("trajectory_ref"))),
                "benchmark_run_id": case.get("run_id", wrapper_metadata.get("run_id")),
            })

        return {
            "schema": "trustkernel.benchmark.dataset.v2",
            "source": source,
            "suite": suite,
            "dataset_version": dataset_version,
            "wrapper": wrapper_key,
            "wrapper_metadata": wrapper_metadata,
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
        dataset = self.import_payload(payload, source=source, suite=suite, dataset_version=dataset_version)
        report = self.run_cases(dataset["cases"], workspace_id=workspace_id)
        report["dataset"] = {key: value for key, value in dataset.items() if key != "cases"}
        return report

    def run_cases(self, cases: Iterable[Dict[str, Any]], workspace_id: str | None = None) -> Dict[str, Any]:
        rows: List[Dict[str, Any]] = []
        for index, case in enumerate(cases):
            case_id = str(case.get("id", case.get("task_id", f"case-{index + 1}")))
            kind = _normalise_kind(case)
            expected = {str(item).upper() for item in case.get("expected_decisions", [])}
            dimensions = {
                "source": _normalise_text(case.get("source"), "unspecified"),
                "suite": _normalise_text(case.get("suite"), "unspecified"),
                "attack": _normalise_text(case.get("attack", case.get("attack_name")), "none"),
                "defense": _normalise_text(case.get("defense", case.get("defense_name")), "trustkernel"),
                "model": _normalise_text(case.get("model", case.get("model_name")), "unspecified"),
                "user_task_id": case.get("user_task_id", case.get("user_task")),
                "injection_task_id": case.get("injection_task_id", case.get("injection_task")),
                "trace_ref": case.get("trace_ref", case.get("trace_url", case.get("trajectory_ref"))),
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
                    "attack_stopped": kind == "attack" and decision in _ATTACK_STOP_DECISIONS,
                    "benign_completed": kind == "benign" and decision in _BENIGN_SUCCESS_DECISIONS,
                })
            except (KeyError, ValidationError, TypeError, ValueError) as exc:
                rows.append({"id": case_id, "kind": kind, **dimensions, "error": str(exc), "correct": False})

        valid_rows = [row for row in rows if "decision" in row]
        attack_rows = [row for row in valid_rows if row.get("kind") == "attack"]
        benign_rows = [row for row in valid_rows if row.get("kind") == "benign"]
        latencies = [float(row["latency_ms"]) for row in valid_rows if row.get("latency_ms") is not None]
        decisions = Counter(row["decision"] for row in valid_rows)

        attack_stops = sum(bool(row.get("attack_stopped")) for row in attack_rows)
        benign_completions = sum(bool(row.get("benign_completed")) for row in benign_rows)
        attack_block_rate = _rate(attack_stops, len(attack_rows))
        benign_completion_rate = _rate(benign_completions, len(benign_rows))
        attack_escape_rate = round(1 - attack_block_rate, 4) if attack_block_rate is not None else None
        false_positive_rate = _rate(sum(row["decision"] in _ATTACK_STOP_DECISIONS for row in benign_rows), len(benign_rows))

        grouped: Dict[str, Dict[str, Dict[str, Any]]] = {}
        for dimension in _PROVENANCE_DIMENSIONS:
            buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for row in valid_rows:
                buckets[str(row.get(dimension, "unspecified"))].append(row)
            grouped[dimension] = {}
            for name, bucket in sorted(buckets.items()):
                attacks = [row for row in bucket if row.get("kind") == "attack"]
                benign = [row for row in bucket if row.get("kind") == "benign"]
                stopped = sum(bool(row.get("attack_stopped")) for row in attacks)
                completed = sum(bool(row.get("benign_completed")) for row in benign)
                grouped[dimension][name] = {
                    "cases": len(bucket),
                    "attack_cases": len(attacks),
                    "attack_block_rate": _rate(stopped, len(attacks)),
                    "attack_block_rate_ci95": _wilson(stopped, len(attacks)),
                    "benign_cases": len(benign),
                    "benign_completion_rate": _rate(completed, len(benign)),
                    "benign_completion_rate_ci95": _wilson(completed, len(benign)),
                    "expected_outcome_rate": _rate(sum(bool(row.get("correct")) for row in bucket), len(bucket)),
                }

        provenance = {dimension: _unique(valid_rows, dimension) for dimension in _PROVENANCE_DIMENSIONS}
        rows_sha256 = _dataset_digest(rows)
        return {
            "schema": "trustkernel.benchmark.v3",
            "report_format_version": 4,
            "warning": (
                "Imported or synthetic benchmark results are regression/evaluation evidence only; "
                "they are not production security accuracy, certification, or a real-world guarantee."
            ),
            "agentdojo_alignment": {
                "style": "AgentDojo-inspired provenance dimensions",
                "native_metrics_inferred": False,
                "note": (
                    "TrustKernel does not relabel policy decisions as AgentDojo utility or targeted ASR. "
                    "Native AgentDojo metrics require the upstream task environment, attacks and task validators."
                ),
            },
            "cases": len(rows),
            "executed": len(valid_rows),
            "errors": len(rows) - len(valid_rows),
            "expected_outcome_rate": _rate(sum(bool(r.get("correct")) for r in rows), len(rows)),
            "security": {
                "attack_cases": len(attack_rows),
                "attack_block_rate": attack_block_rate,
                "attack_block_rate_ci95": _wilson(attack_stops, len(attack_rows)),
                "attack_escape_rate": attack_escape_rate,
                "metric_scope": "TrustKernel runtime decisions on imported attack-labelled cases; not AgentDojo targeted ASR",
            },
            "utility": {
                "benign_cases": len(benign_rows),
                "benign_completion_rate": benign_completion_rate,
                "benign_completion_rate_ci95": _wilson(benign_completions, len(benign_rows)),
                "false_positive_rate": false_positive_rate,
                "metric_scope": "TrustKernel execution-permitting decisions on benign-labelled cases; not native task utility",
            },
            "performance": {
                "mean_latency_ms": round(mean(latencies), 4) if latencies else None,
                "max_latency_ms": round(max(latencies), 4) if latencies else None,
            },
            "coverage": {
                "kinds": dict(sorted(Counter(str(row.get("kind", "unspecified")) for row in valid_rows).items())),
                "suites": {name: sum(1 for row in valid_rows if row.get("suite") == name) for name in provenance["suite"]},
                "with_user_task_id": sum(row.get("user_task_id") is not None for row in valid_rows),
                "with_injection_task_id": sum(row.get("injection_task_id") is not None for row in valid_rows),
                "with_trace_ref": sum(bool(row.get("trace_ref")) for row in valid_rows),
            },
            "provenance": provenance,
            "decision_counts": dict(sorted(decisions.items())),
            "breakdown": grouped,
            "rows_sha256": rows_sha256,
            "rows": rows,
        }


benchmark_adapter = BenchmarkAdapter()
