# ADR-017: Production HSTS boundary

- **Status:** Accepted
- **Checkpoint:** TrustKernel v1.4.27 hardening
- **Scope:** Browser transport policy at production HTTP ingress

## Context

TrustKernel already constrains production Host headers and browser CORS origins and emits baseline browser security headers. A production HTTPS deployment should also tell browsers to keep using HTTPS on future requests so a later HTTP navigation cannot silently become a downgrade path.

HTTP Strict Transport Security (HSTS) is persistent browser state. That persistence is useful, but it also means overly broad settings can create availability failures when TLS is not ready on a host or subdomain. `includeSubDomains` expands that scope, and preload requires a separate external browser-list submission with long-lived operational consequences.

## Decision

TrustKernel adds an application-layer HSTS middleware with the following rules:

1. HSTS is emitted only when `TRUSTKERNEL_ENV=production`.
2. `TRUSTKERNEL_HSTS_MAX_AGE` controls the policy lifetime. The production-readiness gate requires at least `31536000` seconds (one year).
3. `TRUSTKERNEL_HSTS_INCLUDE_SUBDOMAINS` defaults off and is added only when the deployment explicitly opts in after confirming every affected subdomain is HTTPS-capable.
4. TrustKernel never emits the `preload` directive automatically. Preload requires a separate domain/TLS ownership review and external submission process.
5. Offline, development, and Judge Mode defaults keep HSTS disabled, preventing local browser environments from receiving persistent HTTPS state.
6. The application may emit HSTS behind a TLS-terminating reverse proxy. Browsers ignore HSTS received over plaintext HTTP, while a correctly terminated HTTPS response preserves the header to the client.

## Rationale

OWASP describes HSTS as a control that upgrades future HTTP navigation to HTTPS and recommends long-lived policies, while also warning that incorrect TLS or subdomain configuration can lock legitimate users out. MDN documents `max-age`, the optional `includeSubDomains` scope expansion, and the stronger prerequisites for browser preload. TrustKernel therefore chooses a long-lived production baseline without silently claiming ownership of all subdomains or enrolling a domain in preload.

## Security boundary

HSTS reduces browser-side downgrade exposure after a browser has learned the policy (or before first contact only when an operator separately uses preload). It does **not** replace valid certificates, TLS termination, reverse-proxy configuration, secure cookies, application authorization, or network security. It is not evidence of production security accuracy or certification.

## Operational consequences

- Production operators must maintain HTTPS for at least the configured `max-age` after browsers receive the header.
- Enabling `includeSubDomains` requires an inventory of present and future subdomains.
- Preload remains an operator-owned process outside TrustKernel runtime configuration.
- To intentionally retire HSTS, operators must plan a staged reduction and ultimately serve `max-age=0` over a valid HTTPS connection; removing the header alone does not immediately erase an existing browser policy.
