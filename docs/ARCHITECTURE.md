# TrustKernel Architecture

TrustKernel is a runtime authorization and security control plane placed between an autonomous AI agent and consequential tools.

## Enforcement path

```text
Human / Application
        ↓
Agent workload identity
        ↓
TrustKernel Gateway
        ↓
Intent + workspace scope
        ↓
Action/dependency graph
        ↓
Provenance + taint propagation
        ↓
Policy-as-code + policy integrity
        ↓
Risk + consequence simulation
        ↓
ALLOW | ALLOW_WITH_LOG | REWRITE | REQUIRE_APPROVAL | BLOCK
        ↓
Real tool executor
        ↓
Hash-chained evidence + incident + telemetry
```

## Core design decisions

1. **Do not trust the model to enforce its own safety.** Deterministic controls sit on every consequential tool boundary.
2. **Identity precedes authorization.** Human operators, workspaces and autonomous agents are distinct principals.
3. **Evaluate causal chains, not isolated calls.** Taint labels and dependency edges expose untrusted-input → sensitive-resource → external-sink paths.
4. **Repair when a safe equivalent is deterministic.** Example: destructive analytics SQL can be rewritten into read-only inspection; protected-branch pushes can be redirected to a feature branch.
5. **High-risk ambiguity escalates to humans.** Human approval is a first-class runtime outcome rather than a UI afterthought.
6. **Evidence is part of the product.** Every decision records policy identity/version/hash, action evidence, graph context and audit-chain position.

## Major modules

- `engines/kernel.py` — orchestration and final decision
- `engines/policy.py` — deterministic authorization rules
- `engines/taint.py` — confidentiality/integrity labels and provenance propagation
- `engines/graph.py` — causal/dependency graph
- `engines/repair.py` — deterministic minimum-change safe alternatives
- `services/workspaces.py` — tenant/API-key lifecycle
- `services/sessions.py` — human member sessions
- `services/workload_identity.py` — Ed25519 agent identities
- `services/policies.py` + `policy_changes.py` — immutable policy bundles and governed promotion
- `services/mcp_registry.py` — trusted MCP server/resource/manifest registry
- `services/incidents.py` + `audit.py` — investigation evidence
- `services/storage.py` — offline-first SQLite persistence

## Hackathon vs production

SQLite, local UI and optional legacy headers keep the event build deterministic and offline-friendly. Production mode should require API keys, signed member sessions, policy-change approval, restricted CORS and non-development signing keys. The interfaces are designed so SQLite can later be replaced by Postgres, local quotas by Redis, and the session adapter by OIDC without changing the enforcement semantics.
