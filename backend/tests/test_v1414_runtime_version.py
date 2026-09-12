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
        "version": "1.4.14",
        "source": "VERSION",
    }
    assert VERSION == "1.4.14"
    assert app.version == "1.4.14"
