from pathlib import Path
import tomllib

from app.benchmarks.adapter import benchmark_adapter
from app.scenarios import SCENARIOS


def test_benchmark_importer_tracks_provenance_digest_and_rejections():
    attack = SCENARIOS["prompt-injection"]["request"]().model_dump(mode="json")
    payload = {
        "source": "agentdojo-style",
        "suite": "workspace",
        "dataset_version": "fixture-1",
        "model": "fixture-model",
        "cases": [
            {
                "task_id": "attack-1",
                "security_label": "prompt_injection",
                "request": attack,
                "expected": "BLOCK",
                "attack_name": "indirect-injection",
                "user_task_id": "user-task-1",
                "injection_task_id": "injection-task-1",
            },
            {"task_id": "broken", "kind": "attack"},
        ],
    }

    imported = benchmark_adapter.import_payload(payload)
    assert imported["schema"] == "trustkernel.benchmark.dataset.v2"
    assert imported["imported"] == 1
    assert imported["rejected"] == 1
    assert len(imported["sha256"]) == 64
    assert imported["cases"][0]["kind"] == "attack"
    assert imported["cases"][0]["suite"] == "workspace"
    assert imported["cases"][0]["model"] == "fixture-model"
    assert imported["cases"][0]["user_task_id"] == "user-task-1"
    assert imported["cases"][0]["injection_task_id"] == "injection-task-1"

    report = benchmark_adapter.run_payload(payload)
    assert report["schema"] == "trustkernel.benchmark.v3"
    assert report["report_format_version"] == 4
    assert report["dataset"]["rejected"] == 1
    assert report["breakdown"]["suite"]["workspace"]["attack_cases"] == 1
    assert report["agentdojo_alignment"]["native_metrics_inferred"] is False
    assert report["coverage"]["with_injection_task_id"] == 1
    assert "production security accuracy" in report["warning"]


def test_sdk_has_pep621_package_metadata():
    config = tomllib.loads(Path("../sdk/pyproject.toml").read_text(encoding="utf-8"))
    project = config["project"]
    assert project["name"] == "trustkernel-sdk"
    assert project["requires-python"] == ">=3.11"
    assert any(dep.startswith("httpx") for dep in project["dependencies"])
