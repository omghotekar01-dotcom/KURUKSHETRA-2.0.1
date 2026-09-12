from app.benchmarks.adapter import benchmark_adapter
from app.scenarios import SCENARIOS


def test_agentdojo_style_provenance_is_preserved_without_metric_overclaim():
    attack = SCENARIOS["prompt-injection"]["request"]().model_dump(mode="json")
    benign = SCENARIOS["safe-analytics"]["request"]().model_dump(mode="json")
    payload = {
        "source": "agentdojo-import",
        "suite": "workspace",
        "dataset_version": "fixture-1",
        "model": "fixture-model",
        "attack": "tool_knowledge",
        "defense": "trustkernel",
        "runs": [
            {
                "id": "workspace-attack",
                "kind": "attack",
                "user_task_id": "user_task_0",
                "injection_task_id": "injection_task_0",
                "trace_ref": "trace://workspace-attack",
                "plan": attack,
                "expected_decision": "BLOCK",
            },
            {
                "id": "workspace-benign",
                "kind": "benign",
                "user_task_id": "user_task_1",
                "attack": "none",
                "plan": benign,
                "expected_decisions": ["ALLOW", "ALLOW_WITH_LOG"],
            },
        ],
    }

    imported = benchmark_adapter.import_payload(payload)
    assert imported["schema"] == "trustkernel.benchmark.dataset.v2"
    assert imported["wrapper"] == "runs"
    assert imported["imported"] == 2
    assert imported["rejected"] == 0
    assert imported["cases"][0]["model"] == "fixture-model"
    assert imported["cases"][0]["suite"] == "workspace"
    assert imported["cases"][0]["injection_task_id"] == "injection_task_0"

    report = benchmark_adapter.run_payload(payload)
    assert report["schema"] == "trustkernel.benchmark.v3"
    assert report["report_format_version"] == 4
    assert report["security"]["attack_cases"] == 1
    assert report["coverage"]["with_injection_task_id"] == 1
    assert report["coverage"]["with_trace_ref"] == 1
    assert report["provenance"]["suite"] == ["workspace"]
    assert report["provenance"]["model"] == ["fixture-model"]
    assert report["agentdojo_alignment"]["native_metrics_inferred"] is False
    assert "not AgentDojo targeted ASR" in report["security"]["metric_scope"]
    assert "not native task utility" in report["utility"]["metric_scope"]
    assert "production security accuracy" in report["warning"]
    assert len(report["rows_sha256"]) == 64


def test_benchmark_importer_rejects_bad_records_and_duplicates():
    plan = SCENARIOS["safe-analytics"]["request"]().model_dump(mode="json")
    imported = benchmark_adapter.import_payload({
        "records": [
            {"id": "dup", "kind": "benign", "plan": plan},
            {"id": "dup", "kind": "benign", "plan": plan},
            {"id": "bad-plan", "kind": "benign", "plan": "not-an-object"},
            "not-an-object",
        ]
    })

    assert imported["imported"] == 1
    assert imported["rejected"] == 3
    messages = {item["error"] for item in imported["errors"]}
    assert "duplicate case id" in messages
    assert "plan/request must be an object" in messages
    assert "case must be an object" in messages
