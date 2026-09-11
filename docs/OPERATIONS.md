# TrustKernel Operations Guide

## Environment variables

```bash
TRUSTKERNEL_DB_PATH=backend/data/trustkernel.db
TRUSTKERNEL_REQUIRE_API_KEY=1
TRUSTKERNEL_POLICY_SIGNING_KEY=<secret-manager-value>
TRUSTKERNEL_A2A_SIGNING_KEY=<secret-manager-value>
TRUSTKERNEL_A2A_MAX_SKEW=300
TRUSTKERNEL_RATE_LIMIT_PER_MINUTE=120
TRUSTKERNEL_DAILY_ACTION_QUOTA=10000
```

For the offline hackathon demo, API-key enforcement can remain optional so Judge Mode works without setup. For a pilot deployment, set `TRUSTKERNEL_REQUIRE_API_KEY=1`.

## Readiness

`GET /ready` checks SQLite availability, policy validation, audit-chain integrity, and deployment security posture.

## Policy release flow

1. Review YAML/policy document.
2. Publish immutable bundle.
3. Verify signature/fingerprint.
4. Propose a governed policy change.
5. Review field-level diff and approval votes.
6. Activate only after threshold is met.
7. Observe runtime policy bundle ID in evaluations.
8. Roll back by promoting an earlier verified bundle.

## MCP onboarding flow

1. Review MCP server and tool manifest.
2. Register canonical resource URI and issuer.
3. Pin manifest SHA-256.
4. Declare minimum scopes.
5. Agent requests a resource-bound token for that canonical server.
6. TrustKernel derives provenance/scope/audience validity from registry state.

## Incident response flow

`OPEN → INVESTIGATING → RESOLVED` (or `FALSE_POSITIVE`)

Use `/api/incidents/{id}/investigation` to view causal graph snapshot, policy evidence, action results and remediation guidance captured at decision time.
