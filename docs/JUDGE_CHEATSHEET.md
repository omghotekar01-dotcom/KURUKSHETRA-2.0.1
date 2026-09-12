# TrustKernel Judge Cheat Sheet — v1.4.10

## One-line pitch
TrustKernel is a runtime security and authorization control plane for autonomous AI agents: it decides what an agent is allowed to do **before** the tool executes, then records auditable evidence of the decision.

## 20-second opener
AI agents can read files, call APIs, use MCP tools, send messages and trigger business actions. Prompt-level safety alone does not give enterprises an execution boundary. TrustKernel places deterministic identity, policy, provenance, approval, risk and audit controls directly on that execution path.

## 90-second demo order
1. **Open the dashboard** — establish that TrustKernel is the control plane, not the agent UI.
2. **Judge Mode** — run the six deterministic scenarios and show ALLOW / REWRITE / APPROVAL / BLOCK decisions.
3. **Policy Studio** — show a structured policy diff and the four-eyes approval path.
4. **Incident Causal Explorer** — open an incident and walk through action chain, finding, remediation and audit evidence.
5. **Identity & governance** — point out OIDC/JWT human identity, workload identity/attestation and governed MCP registry.
6. **Production path** — mention PostgreSQL persistence, distributed quota interface, OpenTelemetry export, non-root container and deployment-readiness checks.

## Judge questions — compact answers

**Why is this not just another prompt firewall?**  
Because TrustKernel enforces decisions at the action/tool boundary. The model can recommend an action, but the runtime still evaluates identity, scope, intent, provenance, policy, risk and approval requirements before execution.

**What happens if the model is compromised?**  
The model does not own the final authorization decision. High-risk actions can be blocked, rewritten to a safer plan, or held for human approval, and the decision is written to the audit/incident trail.

**Can it work with existing agent frameworks?**  
Yes. The Python SDK is framework-agnostic and includes thin integration helpers so LangChain/LangGraph/AutoGen/MCP-style applications can route tool actions through the same enforcement point.

**Is it cloud-only?**  
No. The hackathon demo supports SQLite offline mode. Production-oriented deployment uses PostgreSQL, stricter configuration checks and optional OpenTelemetry export.

**How do you handle identity?**  
Human identity supports standards-based OIDC discovery, exact issuer/audience validation, JWKS rotation and configurable claims/roles. Workload identity adds attestation metadata plus external KMS/HSM/SPIFFE-style signer interfaces.

**What is the moat?**  
TrustKernel combines execution-time authorization, agent/tool provenance, governed policy/MCP changes, deterministic repair/approval outcomes, incident causality and portable evidence in one control plane rather than treating them as separate dashboards.

**Are the benchmark numbers production accuracy?**  
No. Bundled, imported and synthetic benchmark/Judge Mode results are regression and evaluation evidence only. They are not production security accuracy, certification or universal attack coverage.

## Recovery commands

Canonical rehearsal:

```bash
cd backend
python rehearsal.py
```

If local SQLite demo state is corrupted:

```bash
cd backend
python demo_reseed.py --yes
python rehearsal.py
```

Never use the demo reseed path against PostgreSQL; the script intentionally refuses that mode.

## Do not overclaim
- Do not say “100% secure”, “unhackable”, “production certified” or “perfect detection”.
- Do not describe deterministic regression benchmark results as real-world production security accuracy.
- Do say: execution boundary, deterministic policy enforcement, fail-closed checks, auditable evidence, offline demo path, production-oriented adapters and deployment gates.

## Closing line
**Agents can be probabilistic. Their permissions should not be. TrustKernel turns autonomous execution into governed execution.**
