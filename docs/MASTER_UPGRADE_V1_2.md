# TrustKernel v1.2 — Identity & Change-Governance Master Upgrade

## Goal

v1.2 closes two major gaps between a hackathon control-plane demo and a credible startup MVP:

1. Human operator identity must not depend on caller-supplied actor headers.
2. Agent/workload identity and security policy changes need cryptographic identity, replay protection, reviewable diffs, and approval workflows.

## Research basis

- **OWASP Agent Control Standard (ACS), 1 Sep 2026** — inspectable, traceable agents, middleware control hooks, declarative controls, and runtime enforcement. https://genai.owasp.org/resource/agent-control-standard-acs/
- **NIST NCCoE AI/software agent identity concept paper, 5 Feb 2026** — identification, authorization, auditing, non-repudiation, and prompt-injection mitigations for software/AI agents. https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd
- **MCP authorization guidance** — resource/audience binding and prohibition of token passthrough. https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- **OpenTelemetry GenAI observability** — agent/model/tool operations should be traceable using common semantic conventions. https://opentelemetry.io/

## Shipped in v1.2

### Signed member sessions

Workspace-scoped short-lived sessions contain member identity, role, issue/expiry timestamps and a unique session ID. Tokens are HMAC-signed, revocable, and current RBAC is re-read on privileged requests so demotions take effect immediately.

### Governed policy promotion

`publish bundle → propose change → field-level diff → approval-group votes → activate`

The policy-change record stores exact bundle ID, requester, approval group, status, timestamps, structured diff and votes. A rejected request never activates the bundle.

### Ed25519 workload identities

Agents can register Ed25519 public keys scoped to a workspace and agent. Inter-agent envelopes can carry sender, recipient, nonce, timestamp, payload, workload key ID and signature. The runtime verifies ownership, key status, signature, freshness and replay state before policy evaluation.

### HTTP/deployment hardening

v1.2 adds restrictive response headers, safer CORS defaults, environment-specific posture checks and production fail-closed configuration guidance.

## Security invariants

1. A workspace session never authorizes another workspace.
2. Role changes are enforced against current RBAC, not stale token claims.
3. A revoked member session is rejected immediately.
4. A workload key signs only for its registered agent identity.
5. A message nonce is accepted only once inside the replay window.
6. A published policy bundle is immutable and fingerprinted.
7. A governed policy request cannot activate before its approval threshold.
8. Production should reject development signing keys, legacy actor headers, unrestricted CORS and direct policy activation.

## Remaining production gaps

- OIDC/SAML/enterprise SSO adapter.
- KMS/HSM or workload-identity key custody.
- Postgres/migration profile for multi-instance deployments.
- Distributed quota store.
- Real OpenTelemetry SDK/OTLP transport.
- Stronger external benchmark bridge and framework-native adapters.
