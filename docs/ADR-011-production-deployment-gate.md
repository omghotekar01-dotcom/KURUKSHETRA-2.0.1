# ADR-011: Production deployment gate and hardened runtime profile

## Status
Accepted for TrustKernel v1.4.6.

## Context
TrustKernel already runs as a non-root container and has production-oriented identity, governance, persistence and telemetry adapters. A hackathon-safe repository still needs a machine-checkable boundary between demo defaults and production posture so that development conveniences are not mistaken for safe deployment settings.

## Decision
Add a deterministic production-readiness evaluator and CLI that fail closed on unsafe production configuration. The gate requires production mode, API-key enforcement, verified identity rather than the legacy actor header, policy approval and four-eyes governance, explicit CORS origins, rotated signing material, HTTPS OIDC with audience validation, and PostgreSQL persistence. Native OpenTelemetry export is recommended and reported as a warning rather than a blocking error.

Add `docker-compose.production.yml` as an explicit hardened profile. It removes development secret defaults, binds the API to loopback by default, keeps the application filesystem read-only, supplies a bounded tmpfs, drops Linux capabilities, disables privilege escalation, limits process count, and retains the non-root `USER` from the Dockerfile.

SQLite remains supported for offline and judge-demo use; the production readiness gate intentionally requires PostgreSQL so the two operating modes cannot be confused.

## Rationale
Current Docker guidance recommends non-root execution for services that do not need privileges and encourages clean runtime images. Kubernetes security guidance similarly recommends non-root workloads, avoiding privileged execution, minimizing capabilities, and using controls such as `allowPrivilegeEscalation`/`no_new_privs` and read-only root filesystems where compatible.

## Validation
CI runs unit tests, the deterministic regression benchmark, Judge Mode, and the production readiness CLI against a synthetic *configuration fixture*. Passing that fixture proves the guard logic works; it is not evidence that any external production environment is secure.
