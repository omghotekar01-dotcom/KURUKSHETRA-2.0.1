from __future__ import annotations

from fastapi.testclient import TestClient

from app.bootstrap import VERSION, app


def test_runtime_version_is_canonical_release_version():
    client = TestClient(app)
    response = client.get("/api/version")
    assert response.status_code == 200
    body = response.json()
    assert body == {
        "schema": "trustkernel.release-version.v1",
        "version": "1.4.21",
        "source": "VERSION",
    }
    assert VERSION == "1.4.21"
    assert app.version == "1.4.21"


def test_v14_capabilities_use_canonical_release_version():
    client = TestClient(app)
    response = client.get("/api/v14/capabilities")
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == VERSION == "1.4.21"
    assert body["identity"]["external_verifier_adapter"] is True
    assert body["identity"]["bounded_workload_signature_lifetime"] is True
    assert body["identity"]["workload_signature_nonce_binding"] is True
    assert body["identity"]["workload_signature_key_algorithm_binding"] is True
