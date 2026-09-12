from app.services.deployment_readiness import assess_production_readiness


def _production_env() -> dict[str, str]:
    return {
        "TRUSTKERNEL_ENV": "production",
        "TRUSTKERNEL_REQUIRE_API_KEY": "1",
        "TRUSTKERNEL_ALLOW_LEGACY_ACTOR_HEADER": "0",
        "TRUSTKERNEL_REQUIRE_POLICY_APPROVAL": "1",
        "TRUSTKERNEL_POLICY_FOUR_EYES": "1",
        "TRUSTKERNEL_CORS_ORIGINS": "https://console.trustkernel.example",
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
        "TRUSTKERNEL_REDIS_URL": "rediss://redis.internal.example:6379/0",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://otel-collector:4318/v1/traces",
    }


def test_production_profile_passes_readiness_gate():
    report = assess_production_readiness(_production_env())
    assert report.ready is True
    assert all(check.passed for check in report.checks)


def test_development_defaults_fail_closed_for_production_gate():
    report = assess_production_readiness({
        "TRUSTKERNEL_ENV": "development",
        "TRUSTKERNEL_CORS_ORIGINS": "*",
        "TRUSTKERNEL_SESSION_SIGNING_KEY": "trustkernel-dev-session-key",
    })
    assert report.ready is False
    failed = {check.name for check in report.checks if not check.passed and check.severity == "error"}
    assert "production-mode" in failed
    assert "cors-restricted" in failed
    assert "postgres-production-persistence" in failed
    assert "distributed-quota-backend" in failed
    assert "redis-quota-tls" in failed


def test_redis_quota_requires_tls_in_production():
    env = _production_env()
    env["TRUSTKERNEL_REDIS_URL"] = "redis://redis.internal.example:6379/0"
    report = assess_production_readiness(env)
    assert report.ready is False
    redis_tls = next(check for check in report.checks if check.name == "redis-quota-tls")
    assert redis_tls.passed is False
    assert redis_tls.severity == "error"


def test_otel_is_recommended_but_not_a_blocking_security_error():
    env = _production_env()
    env.pop("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    report = assess_production_readiness(env)
    assert report.ready is True
    otel = next(check for check in report.checks if check.name == "native-otel-export-configured")
    assert otel.passed is False
    assert otel.severity == "warning"
