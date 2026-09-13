from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CRITICAL_ASSETS = (
    "README.md",
    "VERSION",
    ".env.example",
    "start.bat",
    "start.sh",
    "Dockerfile",
    "docker-compose.production.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/supply-chain.yml",
    "frontend/index.html",
    "frontend/app.js",
    "backend/app/bootstrap.py",
    "backend/app/v14_api.py",
    "backend/app/benchmarks/adapter.py",
    "backend/app/benchmarks/agentdojo_native.py",
    "backend/app/services/http_security.py",
    "backend/app/services/postgres_storage.py",
    "backend/app/services/quotas.py",
    "backend/app/services/replay.py",
    "backend/app/services/otlp.py",
    "backend/app/services/workload_attestation.py",
    "backend/app/services/kms_signing.py",
    "backend/app/services/deployment_readiness.py",
    "backend/requirements.txt",
    "backend/supply_chain_check.py",
    "backend/rehearsal.py",
    "backend/release_check.py",
    "backend/deployment_check.py",
    "backend/tests/test_v1416_postgres_integration.py",
    "backend/tests/test_v1417_redis_quota_integration.py",
    "backend/tests/test_v1418_otel_hardening.py",
    "backend/tests/test_v1419_benchmark_reporting.py",
    "backend/tests/test_v1420_governance_ui.py",
    "backend/tests/test_v142_workload_attestation.py",
    "backend/tests/test_v1422_sdk_packaging.py",
    "backend/tests/test_v1423_pitch_assets.py",
    "backend/tests/test_v1424_replay_protection.py",
    "backend/tests/test_v1425_http_boundary.py",
    "backend/tests/test_v1426_cors_boundary.py",
    "backend/tests/test_v1427_hsts_boundary.py",
    "backend/tests/test_v1428_agentdojo_native.py",
    "backend/tests/test_v1429_kms_signing.py",
    "docs/adr/ADR-007-v141-production-persistence.md",
    "docs/adr/ADR-012-v1418-otel-production-hardening.md",
    "docs/adr/ADR-013-v1421-workload-envelope-verification.md",
    "docs/adr/ADR-014-v1424-distributed-replay-protection.md",
    "docs/adr/ADR-015-v1425-trusted-host-boundary.md",
    "docs/adr/ADR-016-v1426-production-cors-boundary.md",
    "docs/adr/ADR-017-v1427-production-hsts-boundary.md",
    "docs/adr/ADR-018-v1428-agentdojo-native-evidence.md",
    "docs/adr/ADR-019-v1429-aws-kms-workload-signing.md",
    "docs/JUDGE_RUNBOOK.md",
    "docs/JUDGE_CHEATSHEET.md",
    "docs/JUDGE_ARCHITECTURE.md",
    "docs/HACKATHON_PITCH.md",
    "docs/FINAL_PITCH_ASSETS.md",
    "docs/EVALUATION.md",
    "examples/sdk_guard_quickstart.py",
    "sdk/README.md",
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
        assets.append({"path": relative, "sha256": _sha256(path), "size_bytes": path.stat().st_size})

    return {
        "schema": "trustkernel.submission-manifest.v16",
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