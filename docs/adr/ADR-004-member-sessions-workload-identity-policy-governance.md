# ADR-004: Separate human sessions, workload identity, and policy promotion

**Status:** Accepted in TrustKernel v1.2

## Decision

TrustKernel uses three distinct authorization concepts rather than one shared credential model:

1. **Workspace API keys** authenticate programmatic workspace access.
2. **Member sessions** identify human operators and apply current workspace RBAC.
3. **Workload identity keys** authenticate autonomous agent-to-agent messages.

Security policy publication is separated from policy activation. Activation can be governed by a workspace approval-group workflow with a structured policy diff and immutable target bundle.

## Why

Human operators and autonomous workloads have different credential lifecycles and risk models. A single static workspace secret cannot provide useful attribution or non-repudiation. Policy changes are themselves security-sensitive actions and need the same operational control philosophy that TrustKernel applies to agent actions.

## Consequences

- Better attribution in audit evidence.
- Immediate RBAC effect when roles change.
- Agent messages can use public-key signatures instead of one shared HMAC secret.
- Policy changes become inspectable and approval-gated.
- Additional key/session lifecycle and production identity-provider integration are required.
