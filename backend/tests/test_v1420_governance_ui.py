from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_policy_studio_exposes_review_triage_contract():
    html = _read("frontend/index.html")
    app = _read("frontend/app.js")

    for marker in (
        'id="policyImpact"',
        'id="policySensitiveCount"',
        "SECURITY-SENSITIVE",
        'id="govFourEyes"',
        'id="govEvidence"',
    ):
        assert marker in html

    for marker in (
        "isSecuritySensitivePath",
        "setPolicyDiffFilter",
        "renderPolicyChangeRows",
        "updateGovernanceRail",
        "policyEvidenceState",
    ):
        assert marker in app


def test_incident_explorer_exposes_blast_radius_and_remediation_contract():
    html = _read("frontend/index.html")
    app = _read("frontend/app.js")

    for marker in (
        'id="incidentStats"',
        'id="incidentSecretCount"',
        'id="incidentUntrustedCount"',
        'id="incidentRepairCount"',
    ):
        assert marker in html

    for marker in (
        "resetIncidentStats",
        "secretNodes",
        "untrustedNodes",
        "Causal scope",
        "Recommended remediation",
    ):
        assert marker in app


def test_review_ui_does_not_claim_security_accuracy():
    app = _read("frontend/app.js")
    forbidden = (
        "production security accuracy",
        "100% secure",
        "guaranteed attack protection",
    )
    lowered = app.lower()
    assert all(term not in lowered for term in forbidden)
