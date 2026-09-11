# TrustKernel Startup MVP

## Product thesis

**TrustKernel is the runtime authorization and security control plane for autonomous AI agents.**

It is not primarily a prompt-injection classifier. It sits on the action boundary and decides whether an agent is authorized to perform a real-world side effect.

## Target first customers

1. Coding agents with GitHub, terminal and deployment access.
2. Finance/reconciliation agents handling invoices and payments.
3. Customer-support agents reading email/CRM data and communicating externally.
4. MCP-based internal copilots connecting many enterprise tools.

## MVP job-to-be-done

A developer should be able to:

1. Create a workspace.
2. Register an AI agent and permissions.
3. Put a tool call behind the TrustKernel gateway.
4. Define or activate a policy.
5. See ALLOW / REWRITE / APPROVAL / BLOCK in real time.
6. Approve legitimate high-risk actions.
7. Investigate blocked activity with evidence.
8. Run an attack/evaluation suite.

## Differentiators

- Least-privilege IAM for AI agents.
- Runtime enforcement at tool boundaries.
- Causal action graph + data-flow/provenance labels.
- Deterministic safe plan repair instead of only blocking.
- Human approval as a programmable outcome.
- MCP server/resource/manifest trust registry.
- Signed human sessions + agent workload identities.
- Governed, immutable policy promotion.
- Audit-grade evidence and incident reconstruction.

## Product moat direction

`Action Graph + Agent IAM + Policy Language + Safe Repair + Security Evaluation Dataset + Enterprise Agent Trust Graph`

## Business model direction

Developer, Startup, Business and Enterprise plans can later be metered on protected agents, evaluated actions, retained evidence, policy packs and integrations. Billing is intentionally outside the hackathon MVP.

## Definition of MVP complete

The product is not complete because the dashboard looks good. It is complete when a developer can connect an agent, exercise an actual tool boundary, demonstrate the controls, retrieve evidence, and reproduce results with tests.
