# ADR-006: v1.4 identity discovery, audience restriction, and portable governance evidence

- Status: Accepted
- Date: 2026-09-11
- Scope: TrustKernel v1.4 production-hardening slice

## Context

TrustKernel v1.3 could verify externally issued JWTs from a configured JWKS URL, but a production control plane also needs to validate the identity provider metadata that supplies those keys, tolerate legitimate key rotation, and preserve privileged governance decisions outside the local database.

Relevant standards and guidance:

1. OpenID Connect Discovery 1.0 requires the provider metadata `issuer` to match the issuer identifier used by the relying party and exposes `jwks_uri` for signature verification.
   - https://openid.net/specs/openid-connect-discovery-1_0.html
2. OAuth 2.0 Security Best Current Practice (RFC 9700) recommends access-token privilege restriction and audience restriction, and requires a resource server to reject a token intended for another resource server.
   - https://www.rfc-editor.org/rfc/rfc9700.html
3. SPIFFE models workload identity as a cryptographically verifiable identity document (SVID), with short-lived X.509/JWT identity material supplied through a workload API rather than long-lived shared credentials.
   - https://spiffe.io/docs/latest/spiffe/concepts/
   - https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/
4. OpenTelemetry recommends OTLP and use of a Collector in production, which remains TrustKernel's preferred observability integration model.
   - https://opentelemetry.io/docs/languages/python/exporters/

## Decision

### OIDC discovery hardening

TrustKernel v1.4 SHALL:

- support OpenID Provider discovery from `/.well-known/openid-configuration`;
- require exact equality between configured and discovered issuer identifiers;
- require HTTPS for issuer/discovery/JWKS endpoints by default;
- require and validate the configured token audience;
- allow only explicitly configured signing algorithms;
- reject JWKs marked for non-signing use or with an algorithm conflicting with the JWT header;
- retry the JWKS once on an unknown `kid` to support normal key rotation;
- support bounded clock skew;
- keep static JWKS support for deterministic offline hackathon/test operation;
- expose configurable workspace, email, and role claims plus external-role to TrustKernel-role mapping.

External role mapping is advisory identity normalization. Existing workspace membership remains the authorization source unless a future explicitly reviewed auto-provisioning feature is introduced.

### Portable governance evidence

TrustKernel SHALL export privileged policy and MCP-registry changes as canonical evidence envelopes containing:

- schema and evidence type;
- workspace and subject identifiers;
- the normalized governance record and votes;
- SHA-256 digest;
- signing algorithm and key identifier;
- signature;
- export timestamp.

The initial implementation uses HMAC-SHA256 because TrustKernel already has an offline-first signing model. Production configuration MUST supply a dedicated evidence-signing key. A future KMS/asymmetric adapter can replace the signer without changing the envelope contract.

### Container posture

The production-oriented container SHALL run as a non-root service user and keep its writable database directory explicitly owned by that user.

## Consequences

- OIDC configuration failures become fail-closed instead of silently accepting metadata drift.
- Identity-provider key rotation can recover from an unknown `kid` without restarting TrustKernel.
- Governance history can be exported into SIEM/GRC/ticketing systems and checked for tampering after export.
- Offline demo behavior remains available through static JWKS, SQLite, and local sessions.
- This ADR does not claim certification, compliance, or production security accuracy from bundled synthetic benchmarks.

## Follow-up

Next v1.4 slices should add a database-backend abstraction with PostgreSQL migrations, KMS/SPIFFE-style workload-identity adapters, a distributed quota backend, native OpenTelemetry SDK export, and richer Policy Studio/incident graph views.
