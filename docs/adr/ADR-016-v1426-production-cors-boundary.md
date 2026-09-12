# ADR-016: Production CORS boundary

## Status
Accepted for the v1.4 hardening line.

## Context
TrustKernel can serve a browser UI and exposes credential-bearing APIs. A permissive or malformed CORS configuration can accidentally authorize an unintended browser origin. FastAPI/Starlette recommend explicit origin allow-lists, especially when credentials are involved.

The existing production gate rejected `*`, but it did not distinguish a syntactically valid origin from a URL containing credentials, paths, queries, fragments, or a production origin using plaintext HTTP.

## Decision
`TRUSTKERNEL_CORS_ORIGINS` remains comma-separated and keeps `*` as the offline/development default for hackathon portability.

Production readiness now requires every configured browser origin to:

1. be explicit (no `*` or wildcard host),
2. be an absolute origin with a host,
3. contain no embedded username/password,
4. contain no application path, query, or fragment, and
5. use HTTPS.

Plain `http://localhost`-style origins remain valid in development/demo profiles, but they fail the production HTTPS gate.

This validation is a deployment guardrail, not a claim that CORS is an authentication control. TrustKernel continues to require verified identity, authorization, API-key/session controls, and policy enforcement independently.

## Rationale
FastAPI documents that wildcard origins do not provide the same credentialed cross-origin behavior as explicit origins and recommends explicitly listing origins for browser clients that send Authorization headers or cookies. The stricter production gate makes that recommendation machine-checkable in TrustKernel's deployment posture.

## Consequences
- Existing offline/Judge Mode behavior is preserved.
- Production operators must supply exact HTTPS browser origins.
- A production deployment configured with `http://`, malformed URLs, wildcard origins, or URL paths fails closed before being considered ready.
- Reverse-proxy Host trust remains governed separately by ADR-015.

## Claims boundary
This control improves configuration safety. It is not a security certification and does not convert synthetic/imported benchmark or Judge Mode results into production security accuracy.
