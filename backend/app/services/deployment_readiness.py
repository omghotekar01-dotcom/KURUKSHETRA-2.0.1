from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Mapping
from urllib.parse import urlparse


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


def assess_production_readiness(env: Mapping[str, str]) -> ReadinessReport:
    checks: list[ReadinessCheck] = []

    def add(name: str, passed: bool, detail: str, severity: str = "error") -> None:
        checks.append(ReadinessCheck(name=name, passed=passed, severity=severity, detail=detail))

    add(
        "production-mode",
        env.get("TRUSTKERNEL_ENV", "").strip().lower() == "production",
        "TRUSTKERNEL_ENV must be production for this gate.",
    )
    add(
        "api-key-enforcement",
        _enabled(env, "TRUSTKERNEL_REQUIRE_API_KEY"),
        "API-key enforcement must be enabled for production ingress.",
    )
    add(
        "legacy-actor-header-disabled",
        not _enabled(env, "TRUSTKERNEL_ALLOW_LEGACY_ACTOR_HEADER"),
        "Legacy actor headers must be disabled so identity comes from verified credentials.",
    )
    add(
        "policy-approval-required",
        _enabled(env, "TRUSTKERNEL_REQUIRE_POLICY_APPROVAL"),
        "Policy activation must require approval.",
    )
    add(
        "four-eyes-enabled",
        _enabled(env, "TRUSTKERNEL_POLICY_FOUR_EYES"),
        "Four-eyes governance must remain enabled.",
    )

    cors = env.get("TRUSTKERNEL_CORS_ORIGINS", "").strip()
    add(
        "cors-restricted",
        bool(cors) and cors != "*" and "*" not in {part.strip() for part in cors.split(",")},
        "CORS origins must be an explicit allow-list, never wildcard.",
    )

    for key in (
        "TRUSTKERNEL_SESSION_SIGNING_KEY",
        "TRUSTKERNEL_A2A_SIGNING_KEY",
        "TRUSTKERNEL_POLICY_SIGNING_KEY",
        "TRUSTKERNEL_EVIDENCE_SIGNING_KEY",
    ):
        add(
            f"secret:{key}",
            _strong_secret(env.get(key, "")),
            f"{key} must be rotated, non-placeholder, and at least 32 characters.",
        )

    issuer = env.get("TRUSTKERNEL_OIDC_ISSUER", "")
    add(
        "oidc-issuer-https",
        _https_url(issuer),
        "OIDC issuer must be an absolute HTTPS URL.",
    )
    add(
        "oidc-audience-configured",
        bool(env.get("TRUSTKERNEL_OIDC_AUDIENCE", "").strip()),
        "OIDC audience must be configured and validated.",
    )
    add(
        "oidc-https-required",
        _enabled(env, "TRUSTKERNEL_OIDC_REQUIRE_HTTPS"),
        "OIDC discovery and JWKS HTTPS enforcement must stay enabled.",
    )

    backend = env.get("TRUSTKERNEL_DB_BACKEND", "sqlite").strip().lower()
    database_url = env.get("TRUSTKERNEL_DATABASE_URL", "").strip()
    postgres_ready = backend == "postgres" and database_url.startswith(("postgresql://", "postgresql+psycopg://"))
    add(
        "postgres-production-persistence",
        postgres_ready,
        "Production profile must use the PostgreSQL persistence backend; SQLite remains supported for offline/demo mode.",
    )

    otlp_endpoint = env.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "").strip()
    add(
        "native-otel-export-configured",
        bool(otlp_endpoint),
        "Configure the native OpenTelemetry trace exporter for production observability.",
        severity="warning",
    )

    errors = [check for check in checks if check.severity == "error" and not check.passed]
    return ReadinessReport(ready=not errors, checks=tuple(checks))
