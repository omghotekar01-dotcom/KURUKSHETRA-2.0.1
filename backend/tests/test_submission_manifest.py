from __future__ import annotations

import re

import submission_manifest


def test_submission_manifest_is_complete_and_deterministic():
    first = submission_manifest.build_manifest()
    second = submission_manifest.build_manifest()

    assert first == second
    assert first["schema"] == "trustkernel.submission-manifest.v11"
    assert first["version"] == "1.4.22"
    assert first["complete"] is True
    assert first["missing"] == []
    assert len(first["assets"]) == len(submission_manifest.CRITICAL_ASSETS)


def test_submission_manifest_has_valid_sha256_for_every_asset():
    manifest = submission_manifest.build_manifest()
    expected_paths = set(submission_manifest.CRITICAL_ASSETS)
    actual_paths = {asset["path"] for asset in manifest["assets"]}

    assert actual_paths == expected_paths
    assert "frontend/index.html" in actual_paths
    assert "frontend/app.js" in actual_paths
    assert "backend/app/bootstrap.py" in actual_paths
    assert "backend/app/v14_api.py" in actual_paths
    assert "backend/app/benchmarks/adapter.py" in actual_paths
    assert "backend/app/services/postgres_storage.py" in actual_paths
    assert "backend/app/services/quotas.py" in actual_paths
    assert "backend/app/services/replay.py" in actual_paths
    assert "backend/app/services/otlp.py" in actual_paths
    assert "backend/app/services/workload_attestation.py" in actual_paths
    assert "backend/app/services/deployment_readiness.py" in actual_paths
    assert ".github/workflows/ci.yml" in actual_paths
    assert "backend/tests/test_v1416_postgres_integration.py" in actual_paths
    assert "backend/tests/test_v1417_redis_quota_integration.py" in actual_paths
    assert "backend/tests/test_v1418_otel_hardening.py" in actual_paths
    assert "backend/tests/test_v1419_benchmark_reporting.py" in actual_paths
    assert "backend/tests/test_v1420_governance_ui.py" in actual_paths
    assert "backend/tests/test_v142_workload_attestation.py" in actual_paths
    assert "backend/tests/test_v1422_sdk_packaging.py" in actual_paths
    assert "backend/tests/test_v1423_pitch_assets.py" in actual_paths
    assert "backend/tests/test_v1424_replay_protection.py" in actual_paths
    assert "docs/adr/ADR-012-v1418-otel-production-hardening.md" in actual_paths
    assert "docs/adr/ADR-013-v1421-workload-envelope-verification.md" in actual_paths
    assert "docs/adr/ADR-014-v1424-distributed-replay-protection.md" in actual_paths
    assert "docs/FINAL_PITCH_ASSETS.md" in actual_paths
    for asset in manifest["assets"]:
        assert re.fullmatch(r"[0-9a-f]{64}", asset["sha256"])
        assert asset["size_bytes"] > 0
