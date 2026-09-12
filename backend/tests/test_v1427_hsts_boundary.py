from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.services.http_security import (
    configure_http_security,
    hsts_header_value,
    hsts_max_age,
    hsts_production_ready,
)


def _production_env(**overrides: str) -> dict[str, str]:
    env = {
        "TRUSTKERNEL_ENV": "production",
        "TRUSTKERNEL_ALLOWED_HOSTS": "testserver",
        "TRUSTKERNEL_HSTS_MAX_AGE": "31536000",
        "TRUSTKERNEL_HSTS_INCLUDE_SUBDOMAINS": "0",
    }
    env.update(overrides)
    return env


def test_hsts_is_not_emitted_for_development_profiles():
    env = {"TRUSTKERNEL_ENV": "development", "TRUSTKERNEL_HSTS_MAX_AGE": "63072000"}
    assert hsts_header_value(env) is None


def test_production_hsts_requires_long_lived_max_age():
    assert hsts_max_age(_production_env()) == 31536000
    assert hsts_production_ready(_production_env()) is True
    assert hsts_production_ready(_production_env(TRUSTKERNEL_HSTS_MAX_AGE="86400")) is False
    assert hsts_production_ready(_production_env(TRUSTKERNEL_HSTS_MAX_AGE="not-an-int")) is False
    assert hsts_header_value(_production_env(TRUSTKERNEL_HSTS_MAX_AGE="0")) is None


def test_include_subdomains_is_explicit_and_preload_is_never_automatic():
    assert hsts_header_value(_production_env()) == "max-age=31536000"
    value = hsts_header_value(_production_env(TRUSTKERNEL_HSTS_INCLUDE_SUBDOMAINS="1"))
    assert value == "max-age=31536000; includeSubDomains"
    assert "preload" not in value.lower()


def test_hsts_middleware_emits_header_for_production_response():
    app = FastAPI()
    configure_http_security(app, _production_env())

    @app.get("/health")
    def health() -> dict[str, bool]:
        return {"ok": True}

    response = TestClient(app, base_url="https://testserver").get("/health")
    assert response.status_code == 200
    assert response.headers["strict-transport-security"] == "max-age=31536000"


def test_hsts_middleware_keeps_local_demo_free_of_persistent_policy():
    app = FastAPI()
    configure_http_security(
        app,
        {
            "TRUSTKERNEL_ENV": "development",
            "TRUSTKERNEL_ALLOWED_HOSTS": "testserver",
            "TRUSTKERNEL_HSTS_MAX_AGE": "63072000",
        },
    )

    @app.get("/")
    def root() -> dict[str, bool]:
        return {"ok": True}

    response = TestClient(app).get("/")
    assert response.status_code == 200
    assert "strict-transport-security" not in response.headers
