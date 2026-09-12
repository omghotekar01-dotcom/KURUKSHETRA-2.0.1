from __future__ import annotations

from app.services.deployment_readiness import assess_production_readiness
from app.services.http_security import allowed_cors_origins, cors_origin_restricted, cors_origins_https


def _production_env() -> dict[str, str]:
    return {
        "TRUSTKERNEL_ENV": "production",
        "TRUSTKERNEL_REQUIRE_API_KEY": "1",
        "TRUSTKERNEL_ALLOW_LEGACY_ACTOR_HEADER": "0",
        "TRUSTKERNEL_REQUIRE_POLICY_APPROVAL": "1",
        "TRUSTKERNEL_POLICY_FOUR_EYES": "1",
        "TRUSTKERNEL_CORS_ORIGINS": "https://console.trustkernel.example",
        "TRUSTKERNEL_ALLOWED_HOSTS": "api.trustkernel.example",
        "TRUSTKERNEL_HSTS_MAX_AGE": "31536000",
        "TRUSTKERNEL_HSTS_INCLUDE_SUBDOMAINS": "0",
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


def test_cors_parser_preserves_demo_wildcard_and_explicit_origins():
    assert allowed_cors_origins({}) == ["*"]
    env = {"TRUSTKERNEL_CORS_ORIGINS": "https://a.example, https://b.example:8443"}
    assert allowed_cors_origins(env) == ["https://a.example", "https://b.example:8443"]
    assert cors_origin_restricted(env) is True
    assert cors_origins_https(env) is True


def test_cors_rejects_wildcards_credentials_paths_queries_and_fragments():
    invalid = (
        "*",
        "https://*.example.com",
        "https://user:pass@example.com",
        "https://example.com/app",
        "https://example.com?tenant=1",
        "https://example.com#fragment",
        "javascript:alert(1)",
    )
    for origin in invalid:
        assert cors_origin_restricted({"TRUSTKERNEL_CORS_ORIGINS": origin}) is False


def test_plain_http_origin_is_allowed_for_demo_validation_but_not_production_https_gate():
    env = {"TRUSTKERNEL_CORS_ORIGINS": "http://localhost:5173"}
    assert cors_origin_restricted(env) is True
    assert cors_origins_https(env) is False


def test_production_readiness_rejects_plain_http_cors_origin():
    env = _production_env()
    env["TRUSTKERNEL_CORS_ORIGINS"] = "http://console.trustkernel.example"
    report = assess_production_readiness(env)
    assert report.ready is False
    restricted = next(check for check in report.checks if check.name == "cors-restricted")
    https_only = next(check for check in report.checks if check.name == "cors-https-only")
    assert restricted.passed is True
    assert https_only.passed is False
    assert https_only.severity == "error"


def test_production_readiness_accepts_multiple_explicit_https_origins():
    env = _production_env()
    env["TRUSTKERNEL_CORS_ORIGINS"] = "https://console.trustkernel.example,https://admin.trustkernel.example"
    report = assess_production_readiness(env)
    assert next(check for check in report.checks if check.name == "cors-restricted").passed is True
    assert next(check for check in report.checks if check.name == "cors-https-only").passed is True
    assert report.ready is True
