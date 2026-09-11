# TrustKernel Threat Model

## Assets

TrustKernel protects credentials, customer/enterprise data, money movement, databases, source repositories, tool permissions, agent memory, inter-agent messages, MCP resources and security-policy configuration.

## Trust boundaries

- Human operator ↔ TrustKernel control plane
- Workspace ↔ workspace
- AI agent ↔ TrustKernel gateway
- Agent ↔ external content (web/email/files)
- Agent ↔ MCP/tool server
- Agent ↔ agent
- Policy author/reviewer ↔ active policy
- TrustKernel ↔ real tool executor

## Primary threats

1. Goal hijack / indirect prompt injection.
2. Tool misuse and destructive side effects.
3. Excessive agent privilege or cross-tenant execution.
4. Poisoned tools, skills, MCP manifests or dependencies.
5. Unexpected command/code execution.
6. Memory/context poisoning.
7. Spoofed, replayed or unauthenticated agent-to-agent messages.
8. Cascading workflow/fan-out failures.
9. Human over-trust in confident agent explanations.
10. Rogue/unregistered agents and privilege escalation.
11. Secret/PII egress to untrusted sinks.
12. Policy tampering or unsafe policy activation.
13. Stolen/replayed workspace credentials.
14. MCP token passthrough, wrong audience/resource, excessive scopes.

## Controls

- Workspace-scoped API keys, rotation and revocation.
- Human member RBAC and signed expiring sessions.
- Ed25519 workload identity registry for agents.
- Least-privilege tool/operation allowlists.
- Information-flow labels and causal dependency graph.
- MCP trust registry with manifest hash, canonical resource and scope checks.
- Replay-resistant nonce/timestamp checks.
- Signed immutable policy bundles and governed policy promotion.
- Safe deterministic plan repair.
- Approval groups for high-impact actions.
- Hash-chained audit ledger and persistent incidents.
- Rate/usage limits and security telemetry.

## Safety boundary of the hackathon build

All destructive, payment and data-exfiltration demonstrations are simulations. TrustKernel does not intentionally attack external services, perform real payments, delete production data or exfiltrate real credentials.

## Residual risk

The MVP does not claim complete protection from novel semantic attacks, compromised host operating systems, malicious administrators, stolen signing keys, model-provider compromise or vulnerabilities inside downstream tools. Real deployments still require normal secure SDLC, secret management, IAM, network controls, endpoint protection and monitoring.
