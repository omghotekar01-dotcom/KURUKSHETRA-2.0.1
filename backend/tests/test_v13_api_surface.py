from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.bootstrap import app


client = TestClient(app)


def test_v13_bootstrap_and_capabilities():
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["version"] == "1.3.0"

    capabilities = client.get("/api/v13/capabilities")
    assert capabilities.status_code == 200
    body = capabilities.json()
    assert body["version"] == "1.3.0"
    assert "oidc_jwt" in body["identity"]
    assert "signed_mcp_registry_changes" in body["governance"]


def test_v13_workload_key_rotation_over_http():
    workspace = client.post(
        "/api/workspaces",
        json={"name": "v13-http", "owner_email": "owner-v13@example.test"},
    ).json()
    workspace_id = workspace["id"]
    headers = {
        "X-TrustKernel-Key": workspace["api_key"],
        "X-TrustKernel-Actor": "owner-v13@example.test",
    }

    public_pem = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    response = client.post(
        f"/api/v13/workspaces/{workspace_id}/workload-identities/demo-agent/rotate",
        headers=headers,
        json={"public_key_pem": public_pem},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["posture"]["active_keys"] == 1
    assert body["posture"]["single_active_key"] is True
