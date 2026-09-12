from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CRITICAL_ASSETS = (
    "README.md",
    "VERSION",
    "start.bat",
    "start.sh",
    "Dockerfile",
    "docker-compose.production.yml",
    ".github/workflows/supply-chain.yml",
    "frontend/index.html",
    "backend/app/bootstrap.py",
    "backend/requirements.txt",
    "backend/supply_chain_check.py",
    "backend/rehearsal.py",
    "backend/release_check.py",
    "backend/deployment_check.py",
    "docs/JUDGE_RUNBOOK.md",
    "docs/JUDGE_CHEATSHEET.md",
    "docs/JUDGE_ARCHITECTURE.md",
    "docs/HACKATHON_PITCH.md",
    "docs/EVALUATION.md",
    "examples/sdk_guard_quickstart.py",
    "sdk/pyproject.toml",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest() -> dict:
    version_path = ROOT / "VERSION"
    version = version_path.read_text(encoding="utf-8").strip() if version_path.is_file() else None
    assets: list[dict] = []
    missing: list[str] = []

    for relative in CRITICAL_ASSETS:
        path = ROOT / relative
        if not path.is_file():
            missing.append(relative)
            continue
        assets.append(
            {
                "path": relative,
                "sha256": _sha256(path),
                "size_bytes": path.stat().st_size,
            }
        )

    return {
        "schema": "trustkernel.submission-manifest.v2",
        "version": version,
        "algorithm": "sha256",
        "complete": not missing,
        "missing": missing,
        "assets": assets,
        "claims_note": (
            "This manifest proves byte-level identity for listed repository assets only; "
            "it is not a security certification or proof of production security accuracy."
        ),
    }


def main() -> int:
    manifest = build_manifest()
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0 if manifest["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
