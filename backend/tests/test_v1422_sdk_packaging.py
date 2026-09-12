from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_sdk_distribution_contract_is_bound_to_release_and_ci():
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    with (ROOT / "sdk/pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert project["version"] == version == "1.4.22"
    assert "Build and validate Python SDK distribution" in workflow
    assert 'python -m pip install "build>=1.2,<2" "twine>=7,<8"' in workflow
    assert "python -m build sdk" in workflow
    assert "python -m twine check sdk/dist/*" in workflow
    assert "python -m pip install --force-reinstall sdk/dist/*.whl" in workflow
    assert 'version("trustkernel-sdk") == "1.4.22"' in workflow
    assert 'joinpath("py.typed").is_file()' in workflow


def test_sdk_release_assets_and_example_exist():
    assert (ROOT / "sdk/trustkernel/py.typed").is_file()
    assert (ROOT / "examples/sdk_guard_quickstart.py").is_file()
    assert (ROOT / "sdk/README.md").is_file()
