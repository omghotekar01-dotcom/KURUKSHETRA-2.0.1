# TrustKernel — hackathon pitch kit

## One-line pitch
**TrustKernel is the trust control plane for AI agents: it verifies who is acting, what they may touch, why the action is allowed, and how to prove or repair what happened.**

## 20-second opener
AI agents are becoming capable enough to send money, modify data, call tools and coordinate with other agents. The missing layer is not another model—it is a runtime trust kernel. TrustKernel sits between agents and real actions to enforce identity, policy, provenance, quotas and human governance, while preserving an audit trail and remediation path.

## The problem
Agent frameworks optimize for capability and speed. Production teams still need answers to five uncomfortable questions: who initiated this action, which workload actually executed it, what policy allowed it, whether untrusted data influenced it, and what can be proven after an incident.

## What we built
TrustKernel combines verified human OIDC/JWT identity, signed workload identity and attestation, replay-resistant agent messaging, governed MCP registry and resource/scope enforcement, action-graph taint/provenance analysis, policy/risk/repair engines, persistent incidents and approvals, signed change evidence, distributed quota adapters, OpenTelemetry export, PostgreSQL persistence, framework guards, benchmark tooling, and a judge-visible Policy Studio + incident causal explorer.

## Demo flow — 90 seconds
1. Start in Judge Mode and show the six curated scenarios.
2. Trigger an unsafe or tainted agent action; show TrustKernel blocking or repairing it before execution.
3. Open the causal graph to show where risk entered the chain and the proposed remediation timeline.
4. Open Policy Studio; show a policy diff, four-eyes approval and signed evidence of the governance change.
5. Show identity/workload posture, audit-chain integrity and OpenTelemetry-ready observability.
6. End on the production-readiness gate: demo defaults are intentionally distinct from the hardened production profile.

## Judge questions
**Is this just an agent firewall?** No. Firewalls filter requests; TrustKernel binds human identity, workload identity, policy, provenance, governance and evidence across the full action lifecycle.

**Does it require one framework?** No. The core is framework-neutral, with lightweight guards for LangChain, LangGraph, AutoGen and MCP SDK-style integrations.

**Are benchmark numbers production accuracy?** No. Synthetic/imported benchmark results are regression and evaluation evidence only, never a claim of production security accuracy or certification.

**Why would a company buy this?** Teams adopting agents need a reusable control plane instead of rebuilding identity, policy, audit, approval, quota and incident logic inside every agent application.

**What is the moat?** The value compounds in the cross-layer evidence graph: identity + workload + policy decision + taint/provenance + governance + remediation, represented in one runtime model and portable evidence trail.

## Business path
Start with developer SDK + self-hosted control plane for teams shipping internal agents. Expand into enterprise policy packs, managed evidence retention, SIEM/observability integrations, KMS/SPIFFE adapters, fleet governance and compliance reporting.

## Closing line
**Agents can be autonomous without being unauditable. TrustKernel makes every consequential action attributable, governable and repairable.**
