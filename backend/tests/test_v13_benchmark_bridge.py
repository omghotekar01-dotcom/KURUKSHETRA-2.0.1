from app.benchmarks.adapter import benchmark_adapter
from app.scenarios import SCENARIOS


def test_benchmark_bridge_reports_security_and_utility():
    attack = SCENARIOS["prompt-injection"]["request"]().model_dump(mode="json")
    benign = SCENARIOS["safe-analytics"]["request"]().model_dump(mode="json")
    report = benchmark_adapter.run_cases([
        {"id": "attack-1", "kind": "attack", "plan": attack, "expected_decisions": ["BLOCK"]},
        {"id": "benign-1", "kind": "benign", "plan": benign, "expected_decisions": ["ALLOW", "ALLOW_WITH_LOG"]},
    ])

    assert report["schema"] == "trustkernel.benchmark.v3"
    assert report["security"]["attack_cases"] == 1
    assert report["security"]["attack_block_rate"] == 1.0
    assert report["utility"]["benign_cases"] == 1
    assert report["utility"]["benign_completion_rate"] == 1.0
    assert report["expected_outcome_rate"] == 1.0
    assert report["agentdojo_alignment"]["native_metrics_inferred"] is False
