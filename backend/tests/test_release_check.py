from __future__ import annotations

import release_check


def test_release_check_is_green_for_repository_checkpoint():
    result = release_check.run()
    assert result["passed"] is True
    assert result["status"] == "release-ready"
    assert result["version"] == "1.4.12"
    assert result["schema"] == "trustkernel.release-check.v2"
    assert all(check["passed"] for check in result["checks"])


def test_release_check_reports_expected_gate_names():
    result = release_check.run()
    names = {check["name"] for check in result["checks"]}
    assert names == {
        "required_submission_assets",
        "version_coherence",
        "claims_discipline",
        "production_compose_posture",
        "submission_manifest",
    }
