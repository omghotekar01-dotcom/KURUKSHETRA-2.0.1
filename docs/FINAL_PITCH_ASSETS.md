# TrustKernel — final hackathon pitch assets

This file is the canonical judge-facing narrative for the current stable v1.4 line. It is intentionally conservative about evidence: synthetic/imported benchmark and Judge Mode results are regression/evaluation evidence, not production security accuracy, certification, or guaranteed attack coverage.

## 12-second hook
**AI agents can act faster than humans can audit them. TrustKernel is the trust control plane that makes consequential agent actions attributable, policy-bound, governable, observable, and repairable before they become invisible incidents.**

## 30-second pitch
Teams are giving AI agents access to money, customer data, cloud tools, code and internal workflows, but the security model is still fragmented across application code. TrustKernel sits between an agent and real-world actions. It binds verified human identity to workload identity, checks policy and provenance, controls MCP/tool access, enforces quotas, records tamper-evident governance evidence, and builds an incident causal graph with a remediation path. The result is one framework-neutral control plane instead of rebuilding trust logic inside every agent application.

## 90-second demo story
1. **Show autonomy with a boundary.** Open Judge Mode and choose a curated scenario where an agent attempts a sensitive or tainted action.
2. **Show the decision before execution.** Highlight identity, requested resource/scope, policy decision, provenance/taint and quota context.
3. **Show repair, not only blocking.** Surface the safe-plan/remediation path so TrustKernel demonstrates how work can continue safely.
4. **Show the causal graph.** Open the incident explorer and trace the risky input/action chain, blast radius, trust-boundary hops and remediation timeline.
5. **Show governance.** Open Policy Studio, review the semantic policy diff, demonstrate four-eyes approval, and show signed governance evidence.
6. **Show production posture.** Point to PostgreSQL persistence, distributed Redis quota support, OpenTelemetry export, workload-signature/KMS-SPIFFE adapter boundaries, non-root container runtime, package-validated SDK, supply-chain audit/SBOM and release provenance.
7. **Close with the boundary.** Demo/benchmark results prove repeatable product behavior and evaluation coverage; they do not claim production security accuracy.

## 3-minute pitch structure
### 0:00–0:25 — Problem
AI-agent stacks are excellent at deciding *what to do*. Enterprises still need a reliable answer to *who authorized it, which workload executed it, what policy allowed it, what untrusted context influenced it, and what evidence remains afterward*.

### 0:25–0:55 — Product
TrustKernel is a runtime trust layer for agent actions. It combines identity, workload attestation, policy, MCP governance, provenance/taint, approvals, quotas, incident reasoning, audit evidence and observability behind one API/SDK boundary.

### 0:55–1:55 — Live proof
Run one unsafe scenario. Show the pre-execution decision. Follow the causal graph. Apply or explain the safe repair. Open Policy Studio and show the governed change path and evidence envelope.

### 1:55–2:30 — Why this can become a startup
The customer is not buying another chatbot or framework. The customer is buying a reusable control plane that can sit across many agent applications. The initial wedge is developer SDK + self-hosted runtime; expansion paths include managed fleet governance, policy packs, evidence retention, SIEM/observability integrations and deployment-owned KMS/SPIFFE adapters.

### 2:30–3:00 — Defensibility and close
The moat is the cross-layer evidence model: human identity + workload identity + requested action + policy decision + provenance + approval + incident graph + remediation, all tied together. **Agents can be autonomous without being unauditable.**

## Slide map
1. **Autonomy has a trust gap** — one risky agent action crossing identity, data and tool boundaries.
2. **TrustKernel in one diagram** — agent → TrustKernel → policy/identity/provenance/quota → tool/action; evidence and telemetry emitted alongside.
3. **Live decision** — show allow/deny/repair context rather than abstract architecture alone.
4. **Incident causal graph** — explain where risk entered, what it touched and what to repair.
5. **Policy Studio** — semantic diff, four-eyes review, activation and signed evidence.
6. **Production path** — PostgreSQL, Redis quota, OTLP, workload adapter boundary, non-root runtime, SDK package validation and supply-chain evidence.
7. **Evaluation with claim discipline** — benchmark/Judge Mode as regression/evaluation evidence only.
8. **Startup path** — SDK/self-hosted wedge → enterprise governance/evidence integrations.
9. **Close** — “Every consequential agent action should be attributable, governable and repairable.”

## Judge-proof claim matrix
| What we may say | Evidence to show | What we must not imply |
| --- | --- | --- |
| TrustKernel evaluates agent actions before execution | live Judge Mode/API decision | universal prevention of all attacks |
| Policies and registry changes produce signed governance evidence | evidence envelope + verification path | external certification |
| PostgreSQL and Redis-backed production adapters exist and are CI-tested | live integration CI / code path | unlimited production scale |
| Native OTLP export exists with production transport checks | OTLP implementation/readiness gate | telemetry guarantees detection |
| Workload signature/attestation adapter boundaries exist | workload envelope + verifier interfaces | that a `spiffe://` string alone proves an SVID |
| SDK distributions are built and installed in CI | wheel/sdist CI gate | package ecosystem maturity beyond current release |
| Benchmark/Judge Mode results are reproducible evaluation evidence | benchmark report / Judge Mode | production security accuracy, certification, or guaranteed real-world coverage |

## Fast judge Q&A
**Why is this not just an agent firewall?** A firewall filters traffic. TrustKernel binds human identity, workload identity, policy, provenance, tool governance, approvals, quota state, evidence and remediation around an action lifecycle.

**Why not put these checks directly in every agent app?** That duplicates security logic, creates inconsistent evidence, and makes policy changes harder to govern. TrustKernel centralizes the control model while exposing framework-neutral integration points.

**Is SPIFFE/KMS already a managed provider integration?** The core provides provider-neutral signing/verifier and attestation metadata interfaces. Deployment-owned adapters must perform real provider certificate/token, key-custody and trust-bundle verification.

**How do you know it works?** We demonstrate deterministic tests, live PostgreSQL/Redis integration paths, production-readiness checks, Judge Mode scenarios, benchmark tooling, supply-chain checks and release provenance. Those are engineering/evaluation evidence, not a claim of perfect real-world security.

**What would you build next with more time?** Managed deployment adapters for enterprise KMS/SPIFFE, richer multi-tenant operations, policy packs, SIEM integrations, larger external benchmark suites, and fleet-level governance analytics.

## Demo recovery plan
- If internet access is unreliable, use SQLite/Judge Mode and the local curated scenarios.
- If PostgreSQL/Redis are unavailable at the venue, explain that CI exercises the production adapters and keep the live demo on offline-safe defaults.
- If an external OIDC provider is unavailable, demonstrate the configured verification path without weakening production HTTPS/audience/issuer checks.
- If a telemetry collector is unavailable, show the native OTLP configuration/readiness behavior rather than fabricating exported traces.
- Never replace a failed dependency with a fake success screen; switch to a deterministic local scenario and state the boundary.

## Final close
**TrustKernel turns agent autonomy into controlled autonomy: every consequential action can be tied to an identity, a policy decision, a provenance trail, a governance record, and a remediation path.**
