# Judge Q&A

## Is this just a prompt-injection detector?
No. Prompt injection is one input threat. TrustKernel's primary enforcement point is the **tool/action boundary**. It verifies identity, scope, provenance, policy, information flow and consequences before allowing the action.

## Why not just use a stronger system prompt?
System prompts are model instructions, not deterministic authorization. A compromised or confused agent still needs an external boundary that can refuse or transform unauthorized tool calls.

## What is technically unique here?
The combination of agent IAM, causal action graphs, provenance/taint tracking, deterministic policy-as-code, minimum-change plan repair, governed approvals and audit-grade evidence in one runtime control plane.

## How do you avoid blocking useful automation?
There are five outcomes, not only allow/block: `ALLOW`, `ALLOW_WITH_LOG`, `REWRITE`, `REQUIRE_APPROVAL`, and `BLOCK`. Safe repair and selective approval preserve useful autonomy.

## What happens if the AI hallucinates a tool call?
The model can propose anything; the gateway still evaluates authorization. An unregistered tool/operation or agent identity can be blocked before execution.

## How are MCP tools protected?
Workspace trust registry, canonical resource URI, manifest fingerprint, issuer/scope metadata, audience/resource validation, and token-passthrough prevention.

## How do agents authenticate to each other?
The MVP supports Ed25519 workload public keys plus nonce/timestamp replay defense. The design can later map to workload-identity systems/KMS without changing the runtime policy contract.

## Why SQLite?
Hackathon reliability and offline operation. The persistence interfaces separate storage from enforcement so production can move to Postgres/managed databases.

## How did you evaluate it?
Automated tests plus a deterministic 19-scenario Attack Lab covering OWASP Agentic ASI01–ASI10. We explicitly label this as regression evidence, not 100% real-world security accuracy. External benchmark integration is part of the roadmap.

## Startup use case?
Companies deploying coding, finance, support or MCP-connected agents need least-privilege permissions, human approval for sensitive actions, incident evidence, and control over what autonomous software may actually execute.

## What is the business moat?
Over time: action/identity graph, policy language, repair engine, agent-security evaluation data, integrations and enterprise trust graph.
