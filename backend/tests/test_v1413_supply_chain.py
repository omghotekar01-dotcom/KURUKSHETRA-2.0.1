from pathlib import Path

import supply_chain_check


def test_repository_requirements_are_exactly_pinned():
    result = supply_chain_check.run()
    assert result["passed"] is True
    assert result["direct_component_count"] >= 10
    assert len(result["sha256"]) == 64
    assert result["violations"] == []


def test_supply_chain_gate_rejects_unpinned_and_remote_requirements(tmp_path: Path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "fastapi>=0.115\n"
        "demo @ https://example.invalid/demo.whl\n"
        "-e ../local-package\n",
        encoding="utf-8",
    )
    result = supply_chain_check.run(requirements)
    assert result["passed"] is False
    assert len(result["violations"]) == 3


def test_supply_chain_gate_accepts_markered_exact_pins(tmp_path: Path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("httpx==0.28.1 ; python_version >= '3.11'\n", encoding="utf-8")
    result = supply_chain_check.run(requirements)
    assert result["passed"] is True
    assert result["direct_components"] == ["httpx==0.28.1"]
