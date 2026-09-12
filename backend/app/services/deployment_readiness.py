from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Mapping
from urllib.parse import urlparse

from .http_security import cors_origin_restricted, cors_origins_https, host_header_restricted, hsts_production_ready


_TRUE = {"1", "true", "yes", "on"}
_WEAK_MARKERS = ("change-me", "dev-only", "trustkernel-dev", "example", "password")


@dataclass(frozen=True)
class ReadinessCheck:
    name: str
    passed: bool
    severity: str
    detail: str


@dataclass(frozen=True)
class ReadinessReport:
    ready: bool
    checks: tuple[ReadinessCheck, ...]

    def to_dict(self) -> dict:
        return {"ready": self.ready, "checks": [asdict(check) for check in self.checks]}


def _enabled(env: Mapping[str, str], key: str) -> bool:
    return env.get(key, "").strip().lower() in _TRUE


def _strong_secret(value: str) -> bool:
    candidate = value.strip()
    lowered = candidate.lower()
    return len(candidate) >= 32 and not any(marker in lowered for marker in _WEAK_MARKERS)


def _https_url(value: str) -> bool:
    parsed = urlparse(value.strip())
    return parsed.scheme == "https" and bool(parsed.netloc)


def _otel_endpoint(env: Mapping[str, str]) -> str:
    traces = env.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "").strip()
    if traces:
        return traces
    return env.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()


def assess_production_readiness(env: Mapping[str, str]) -> ReadinessReport:
    checks: list[ReadinessCheck] = []

    def add(name: str, passed: bool, detail: str, severity: str = "error") -> None:
        checks.append(ReadinessCheck(name=name, passed=passed, severity=severity, detail=detail))

    add("production-mode", env.get("TRUSTKERNEL_ENV", "").strip().lower() == "production", "TRUSTKERNEL_ENV must be production for this gate.")
    add("api-key-enforcement", _enabled(env, "TRUSTKERNEL_REQUIRE_API_KEY"), "API-key enforcement must be enabled for production ingress.")
    add("legacy-actor-header-disabled", not _enabled(env, "TRUSTKERNEL_ALLOW_LEGACY_ACTOR_HEADER"), "Legacy actor headers must be disabled so identity comes from verified credentials.")
    add("policy-approval-required", _enabled(env, "TRUSTKERNEL_REQUIRE_POLICY_APPROVAL"), "Policy activation must require approval.")
    add("four-eyes-enabled", _enabled(env, "TRUSTKERNEL_POLICY_FOUR_EYES"), "Four-eyes governance must remain enabled.")

    add("cors-restricted", cors_origin_restricted(env), "CORS origins must be explicit absolute HTTP(S) origins with no wildcard, credentials, path, query, or fragment.")
    add("cors-https-only", cors_origins_https(env), "Production browser origins must use HTTPS; plain HTTP origins remain available only for local/demo profiles.")
    add(
        "host-header-restricted",
        host_header_restricted(env),
        "TRUSTKERNEL_ALLOWED_HOSTS must be an explicit Host-header allow-list with no wildcard in production.",
    )
    add(
        "hsts-long-lived",
        hsts_production_ready(env),
        "Production HSTS max-age must be at least 31536000 seconds. includeSubDomains remains an explicit deployment choice and preload is never enabled automatically.",
    )

    for key in ("TRUSTKERNEL_SESSION_SIGNING_KEY", "TRUSTKERNEL_A2A_SIGNING_KEY", "TRUSTKERNEL_POLICY_SIGNING_KEY", "TRUSTKERNEL_EVIDENCE_SIGNING_KEY"):
        add(f"secret:{key}", _strong_secret(env.get(key, "")), f"{key} must be rotated, non-placeholder, and at least 32 characters.")

    issuer = env.get("TRUSTKERNEL_OIDC_ISSUER", "")
    add("oidc-issuer-https", _https_url(issuer), "OIDC issuer must be an absolute HTTPS URL.")
    add("oidc-audience-configured", bool(env.get("TRUSTKERNEL_OIDC_AUDIENCE", "").strip()), "OIDC audience must be configured and validated.")
    add("oidc-https-required", _enabled(env, "TRUSTKERNEL_OIDC_REQUIRE_HTTPS"), "OIDC discovery and JWKS HTTPS enforcement must stay enabled.")

    backend = env.get("TRUSTKERNEL_DB_BACKEND", "sqlite").strip().lower()
    database_url = env.get("TRUSTKERNEL_DATABASE_URL", "").strip()
    postgres_ready = backend == "postgres" and database_url.startswith(("postgresql://", "postgresql+psycopg://"))
    add("postgres-production-persistence", postgres_ready, "Production profile must use the PostgreSQL persistence backend; SQLite remains supported for offline/demo mode.")

    quota_backend = env.get("TRUSTKERNEL_QUOTA_BACKEND", "memory").strip().lower()
    redis_url = env.get("TRUSTKERNEL_REDIS_URL", "").strip()
    add("distributed-quota-backend", quota_backend == "redis", "Production profile must use the Redis distributed quota backend so replicas share one enforcement state.")
    add("redis-quota-tls", redis_url.startswith("rediss://"), "Production Redis quota transport must use TLS via a rediss:// URL.")

    replay_backend = env.get("TRUSTKERNEL_REPLAY_BACKEND", "memory").strip().lower()
    add(
        "distributed-replay-backend",
        replay_backend == "redis",
        "Production profile must use the Redis distributed replay guard so signed workload envelope nonces are single-use across replicas.",
    )
    add(
        "redis-replay-tls",
        replay_backend != "redis" or redis_url.startswith("rediss://"),
        "Production Redis replay-state transport must use TLS via the shared rediss:// TRUSTKERNEL_REDIS_URL.",
    )

    otlp_endpoint = _otel_endpoint(env)
    add("native-otel-export-configured", bool(otlp_endpoint), "Configure the native OpenTelemetry trace exporter for production observability.", severity="warning")
    add(
        "otel-export-https",
        not otlp_endpoint or _https_url(otlp_endpoint),
        "When OTLP export is configured in production, the endpoint must use HTTPS. Plain HTTP remains available only for local/demo collectors.",
    )

    errors = [check for check in checks if check.severity == "error" and not check.passed]
    return ReadinessReport(ready=not errors, checks=tuple(checks))
