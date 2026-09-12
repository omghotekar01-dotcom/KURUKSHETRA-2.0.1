from __future__ import annotations

import re

import submission_manifest


def test_submission_manifest_is_complete_and_deterministic():
    first = submission_manifest.build_manifest()
    second = submission_manifest.build_manifest()

    assert first == second
    assert first["schema"] == "trustkernel.submission-manifest.v2"
    assert first["version"] == "1.4.14"
    assert first["complete"] is True
    assert first["missing"] == []
    assert len(first["assets"]) == len(submission_manifest.CRITICAL_ASSETS)


def test_submission_manifest_has_valid_sha256_for_every_asset():
    manifest = submission_manifest.build_manifest()
    expected_paths = set(submission_manifest.CRITICAL_ASSETS)
    actual_paths = {asset["path"] for asset in manifest["assets"]}

    assert actual_paths == expected_paths
    assert "frontend/index.html" in actual_paths
    assert "backend/app/bootstrap.py" in actual_paths
    for asset in manifest["assets"]:
        assert re.fullmatch(r"[0-9a-f]{64}", asset["sha256"])
        assert asset["size_bytes"] > 0
