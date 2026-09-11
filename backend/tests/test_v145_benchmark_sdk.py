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
        "cases": [
            {
                "task_id": "attack-1",
                "security_label": "prompt_injection",
                "request": attack,
                "expected": "BLOCK",
                "attack_name": "indirect-injection",
            },
            {"task_id": "broken", "kind": "attack"},
        ],
    }

    imported = benchmark_adapter.import_payload(payload)
    assert imported["schema"] == "trustkernel.benchmark.dataset.v1"
    assert imported["imported"] == 1
    assert imported["rejected"] == 1
    assert len(imported["sha256"]) == 64
    assert imported["cases"][0]["kind"] == "attack"
    assert imported["cases"][0]["suite"] == "workspace"

    report = benchmark_adapter.run_payload(payload)
    assert report["schema"] == "trustkernel.benchmark.v2"
    assert report["report_format_version"] == 3
    assert report["dataset"]["rejected"] == 1
    assert report["breakdown"]["suite"]["workspace"]["attack_cases"] == 1
    assert "production security accuracy" in report["warning"]


def test_sdk_has_pep621_package_metadata():
    config = tomllib.loads(Path("../sdk/pyproject.toml").read_text(encoding="utf-8"))
    project = config["project"]
    assert project["name"] == "trustkernel-sdk"
    assert project["requires-python"] == ">=3.11"
    assert any(dep.startswith("httpx") for dep in project["dependencies"])
