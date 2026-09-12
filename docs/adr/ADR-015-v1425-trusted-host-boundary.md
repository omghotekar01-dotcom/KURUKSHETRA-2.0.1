# ADR-015 — v1.4.25 trusted Host-header boundary

## Status
Accepted

## Context
TrustKernel already restricts production CORS origins, but CORS is a browser policy and does not validate the HTTP `Host` header seen by the application. A deployment can therefore have a strict browser-origin policy while still accepting requests addressed to an unexpected host name.

FastAPI exposes Starlette's `TrustedHostMiddleware`, whose purpose is to enforce allowed `Host` values and protect applications from HTTP Host-header attacks. TrustKernel also commonly runs behind a reverse proxy, so proxy trust and application host trust must remain explicit deployment decisions rather than being inferred from arbitrary forwarded headers.

## Decision
1. Add `TRUSTKERNEL_ALLOWED_HOSTS` as a comma-separated application Host allow-list.
2. Preserve `*` as the offline/development default so local Judge Mode and ad-hoc localhost demos remain frictionless.
3. Install `TrustedHostMiddleware` during canonical app bootstrap.
4. Make production readiness fail closed when the allow-list is missing, `*`, or contains wildcard host entries.
5. Require the variable in `docker-compose.production.yml` rather than silently inheriting the development wildcard.
6. Surface the control in `/ready` through the existing security posture report.
7. Keep reverse-proxy forwarded-header trust separate. Operators must configure their ASGI server/proxy chain explicitly and should not trust arbitrary forwarding sources.

## Consequences
Production deployments now need to declare their externally valid application hosts, for example `api.trustkernel.example`. Requests carrying an unlisted Host header receive HTTP 400 before reaching TrustKernel routes. Offline/demo behavior is unchanged unless a developer explicitly configures the allow-list.

This control narrows one HTTP ingress attack surface; it is not a substitute for TLS termination, proxy ACLs, OIDC verification, API-key enforcement, workload identity, or other TrustKernel authorization controls.

## References
- FastAPI Advanced Middleware documentation: `TrustedHostMiddleware` protects against HTTP Host Header attacks.
- FastAPI Behind a Proxy documentation: forwarded headers should only be trusted from explicitly trusted proxy sources.
