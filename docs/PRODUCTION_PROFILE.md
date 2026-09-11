# Production profile

TrustKernel remains an offline-first hackathon/startup MVP, but v1.2 distinguishes **demo-safe defaults** from **production expectations**.

## Required production settings

```env
TRUSTKERNEL_ENV=production
TRUSTKERNEL_REQUIRE_API_KEY=1
TRUSTKERNEL_ALLOW_LEGACY_ACTOR_HEADER=0
TRUSTKERNEL_REQUIRE_POLICY_APPROVAL=1
TRUSTKERNEL_CORS_ORIGINS=https://console.example.com
TRUSTKERNEL_SESSION_SIGNING_KEY=<random secret from secret manager>
TRUSTKERNEL_A2A_SIGNING_KEY=<random fallback secret or disable HMAC path>
TRUSTKERNEL_POLICY_SIGNING_KEY=<random secret from secret manager>
```

`GET /api/security/posture` and `GET /ready` surface unsafe production configuration. In production mode, development signing keys, legacy actor-header authentication, unrestricted CORS, or direct policy activation cause the posture check to fail.

## Identity model

- **Workspace API key:** programmatic tenant credential.
- **Member session:** short-lived human-operator credential; current RBAC is re-read per privileged request.
- **Ed25519 workload key:** public-key identity for an autonomous agent workload.

The local member-session exchange is intended for hackathon/demo operation. A hosted product should plug in OIDC/SAML/enterprise SSO and issue the same internal principal contract after external authentication.

## Key custody

The demo workload-key helper returns a private Ed25519 key exactly once. Do not use it in production. Register a public key generated and held by the workload, KMS, HSM, or workload-identity system.

## Policy promotion

For production, direct activation is disabled. Use:

1. publish immutable signed bundle;
2. create policy-change request;
3. inspect structured diff;
4. approve through workspace approval group;
5. allow TrustKernel to activate after threshold is met.

## Current scale boundary

SQLite and in-process quotas are deliberate MVP choices. A multi-instance hosted deployment should move to Postgres plus a distributed quota/cache layer and use real OTLP transport.
