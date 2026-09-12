from __future__ import annotations

import release_check


def test_release_check_is_green_for_repository_checkpoint():
    result = release_check.run()
    assert result["passed"] is True
    assert result["status"] == "release-ready"
    assert result["version"] == "1.4.16"
    assert result["schema"] == "trustkernel.release-check.v6"
    assert all(check["passed"] for check in result["checks"])


def test_release_check_reports_expected_gate_names():
    result = release_check.run()
    names = {check["name"] for check in result["checks"]}
    assert names == {
        "required_submission_assets",
        "version_coherence",
        "runtime_version_binding",
        "claims_discipline",
        "production_compose_posture",
        "postgres_migration_coordination",
        "supply_chain_declarations",
        "artifact_attestation_workflow",
        "submission_manifest",
    }


def test_artifact_attestation_gate_is_green():
    result = release_check.run()
    check = next(item for item in result["checks"] if item["name"] == "artifact_attestation_workflow")
    assert check["passed"] is True
    assert check["missing_markers"] == []


def test_postgres_migration_coordination_gate_is_green():
    result = release_check.run()
    check = next(item for item in result["checks"] if item["name"] == "postgres_migration_coordination")
    assert check["passed"] is True
    assert check["missing_migration_markers"] == []
    assert check["missing_ci_markers"] == []
