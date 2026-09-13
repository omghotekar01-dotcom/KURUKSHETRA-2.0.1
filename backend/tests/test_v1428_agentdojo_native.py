from __future__ import annotations

from app.benchmarks.agentdojo_native import build_agentdojo_report, import_agentdojo_results


def sample_payload():
    return {
        "suite": "workspace",
        "model": "example-model",
        "attack": "important_instructions",
        "defense": "tool_filter",
        "agentdojo_version": "recorded-upstream-version",
        "results": [
            {"user_task_id": "user_task_0", "injection_task_id": "injection_task_0", "utility": True, "security": False, "trace_path": "runs/a.json"},
            {"user_task_id": "user_task_1", "injection_task_id": "injection_task_0", "utility": False, "security": True, "trace_path": "runs/b.json"},
            {"user_task_id": "user_task_2", "utility": True},
        ],
    }


def test_native_import_preserves_upstream_validator_booleans_and_provenance():
    dataset = import_agentdojo_results(sample_payload())

    assert dataset["schema"] == "trustkernel.agentdojo-import.v1"
    assert dataset["semantic_policy"] == "pass-through"
    assert dataset["imported"] == 3
    assert dataset["rejected"] == 0
    assert len(dataset["sha256"]) == 64
    assert dataset["rows"][0]["suite"] == "workspace"
    assert dataset["rows"][0]["utility"] is True
    assert dataset["rows"][0]["security"] is False
    assert dataset["rows"][1]["security"] is True
    assert dataset["rows"][2]["security"] is None
    assert dataset["rows"][0]["trace_ref"] == "runs/a.json"
    assert "production security accuracy" in dataset["warning"]


def test_native_report_does_not_relabel_agentdojo_security_as_trustkernel_accuracy():
    report = build_agentdojo_report(sample_payload())

    assert report["schema"] == "trustkernel.agentdojo-report.v1"
    assert report["summary"]["cases"] == 3
    assert report["summary"]["utility_true_rate"] == 0.6667
    assert report["summary"]["security_true_rate"] == 0.5
    assert report["grouped"]["suite"]["workspace"]["cases"] == 3
    assert report["claims_boundary"]["native_metrics_recomputed"] is False
    assert report["claims_boundary"]["trustkernel_runtime_accuracy_claimed"] is False
    assert report["claims_boundary"]["production_security_claimed"] is False


def test_native_import_rejects_unscored_or_malformed_rows_without_guessing():
    dataset = import_agentdojo_results({"results": [{"utility": True}, {"user_task_id": "user_task_7"}, "bad-row"]})

    assert dataset["imported"] == 0
    assert dataset["rejected"] == 3
    assert {entry["error"] for entry in dataset["errors"]} == {
        "missing user_task_id",
        "missing utility/security validator outputs",
        "result must be an object",
    }
