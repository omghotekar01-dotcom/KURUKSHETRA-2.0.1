from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.services.deployment_readiness import assess_production_readiness
from app.services.http_security import allowed_hosts, configure_http_security, host_header_restricted


def _production_env() -> dict[str, str]:
    return {
        "TRUSTKERNEL_ENV": "production",
        "TRUSTKERNEL_REQUIRE_API_KEY": "1",
        "TRUSTKERNEL_ALLOW_LEGACY_ACTOR_HEADER": "0",
        "TRUSTKERNEL_REQUIRE_POLICY_APPROVAL": "1",
        "TRUSTKERNEL_POLICY_FOUR_EYES": "1",
        "TRUSTKERNEL_CORS_ORIGINS": "https://console.trustkernel.example",
        "TRUSTKERNEL_ALLOWED_HOSTS": "api.trustkernel.example",
        "TRUSTKERNEL_SESSION_SIGNING_KEY": "s" * 48,
        "TRUSTKERNEL_A2A_SIGNING_KEY": "a" * 48,
        "TRUSTKERNEL_POLICY_SIGNING_KEY": "p" * 48,
        "TRUSTKERNEL_EVIDENCE_SIGNING_KEY": "e" * 48,
        "TRUSTKERNEL_OIDC_ISSUER": "https://idp.example.com",
        "TRUSTKERNEL_OIDC_AUDIENCE": "trustkernel-prod",
        "TRUSTKERNEL_OIDC_REQUIRE_HTTPS": "1",
        "TRUSTKERNEL_DB_BACKEND": "postgres",
        "TRUSTKERNEL_DATABASE_URL": "postgresql://trustkernel:secret@postgres:5432/trustkernel",
        "TRUSTKERNEL_QUOTA_BACKEND": "redis",
        "TRUSTKERNEL_REPLAY_BACKEND": "redis",
        "TRUSTKERNEL_REDIS_URL": "rediss://redis.internal.example:6379/0",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "https://otel-collector.example/v1/traces",
    }


def test_allowed_hosts_preserves_offline_wildcard_but_parses_explicit_hosts():
    assert allowed_hosts({}) == ["*"]
    assert host_header_restricted({}) is False
    env = {"TRUSTKERNEL_ALLOWED_HOSTS": "api.example.com, console.example.com"}
    assert allowed_hosts(env) == ["api.example.com", "console.example.com"]
    assert host_header_restricted(env) is True


def test_trusted_host_middleware_blocks_unlisted_host():
    app = FastAPI()
    configure_http_security(app, {"TRUSTKERNEL_ALLOWED_HOSTS": "api.example.com"})

    @app.get("/health")
    def health() -> dict:
        return {"ok": True}

    client = TestClient(app)
    accepted = client.get("/health", headers={"host": "api.example.com"})
    rejected = client.get("/health", headers={"host": "attacker.example"})
    assert accepted.status_code == 200
    assert rejected.status_code == 400
    assert "Invalid host header" in rejected.text


def test_production_readiness_rejects_wildcard_or_missing_hosts():
    for value in ("*", "", "*.trustkernel.example"):
        env = _production_env()
        if value:
            env["TRUSTKERNEL_ALLOWED_HOSTS"] = value
        else:
            env.pop("TRUSTKERNEL_ALLOWED_HOSTS")
        report = assess_production_readiness(env)
        assert report.ready is False
        host_check = next(check for check in report.checks if check.name == "host-header-restricted")
        assert host_check.passed is False
        assert host_check.severity == "error"


def test_production_readiness_accepts_explicit_hosts():
    report = assess_production_readiness(_production_env())
    host_check = next(check for check in report.checks if check.name == "host-header-restricted")
    assert host_check.passed is True
    assert report.ready is True
