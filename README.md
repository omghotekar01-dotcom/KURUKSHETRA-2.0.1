# TrustKernel

**Runtime Security & Authorization Control Plane for Autonomous AI Agents**  
Kurukshetra 2.0 · Open Innovation backup project · Startup MVP v1.2

TrustKernel sits on the execution path between an autonomous AI agent and its tools. It evaluates **identity, workspace scope, user intent, tool provenance, information-flow labels, policy, risk and consequences before execution**, then returns one of five deterministic outcomes:

`ALLOW · ALLOW_WITH_LOG · REWRITE · REQUIRE_APPROVAL · BLOCK`

The product is intentionally not positioned as another prompt filter. Its job is runtime authorization, least privilege, safe plan repair, incident evidence, and operational control for agentic systems.

## v1.2 startup-MVP capabilities

- Framework-agnostic enforcement gateway
- Workspace/tenant onboarding
- Hashed API keys with **rotation + revocation**
- Workspace members + RBAC capabilities
- Approval groups for finance/security decisions
- Workspace-scoped agent identities and cross-tenant blocking
- Agent IAM / least-privilege tool and operation allowlists
- YAML policy-as-code with **version + SHA-256 fingerprint + validation**
- Immutable **signed policy bundles** with workspace activation + rollback
- Dependency-aware causal action graph
- Confidentiality/integrity provenance and taint propagation
- MCP/tool/skill provenance and manifest-integrity controls
- Workspace MCP trust registry with canonical resource URI, issuer, scope allowlist + manifest pinning
- MCP token-passthrough + audience-binding controls
- Durable-memory provenance / poisoning controls
- Inter-agent sender + signature/authenticity checks
- Nonce/timestamp **replay protection** for authenticated inter-agent messages
- Deterministic Safe Plan Repair
- Human approval queue with actor/role evidence
- Persistent incident queue + graph/policy **Incident Investigator**
- Hash-chained tamper-evident audit ledger
- OpenTelemetry-style JSON security telemetry export + OTLP/HTTP JSON-shaped adapter
- Workspace action rate limit + daily quota guard
- Importable external benchmark case adapter
- Python SDK with guarded execution helper
- OWASP Agentic Top 10 Attack Lab
- One-click Judge Mode
- Dependency-light SQLite persistence for hackathon/offline reliability

## Current Attack Lab

The synthetic local suite contains **19 scenarios** and covers **OWASP Agentic Top 10 ASI01–ASI10**.

Examples:
- Indirect prompt injection → secret egress → **BLOCK**
- Destructive SQL generated for analytics → **REWRITE to read-only**
- ₹95,000 payment over ₹50,000 agent limit → **REQUIRE APPROVAL**
- Protected Git push → **REWRITE to feature branch**
- Poisoned MCP tool / bad manifest provenance → **BLOCK**
- MCP token passthrough / audience violation → **BLOCK**
- Memory poisoning / unverified durable-memory provenance → **BLOCK**
- Spoofed or invalidly signed inter-agent message → **BLOCK**
- Excessive workflow fan-out → **REQUIRE APPROVAL**

## Quality gate

Current local checkpoint:
- **47/47 automated tests passing**
- **190 deterministic regression evaluations** (19 scenarios × 10 iterations)
- complete ASI01–ASI10 coverage in the bundled suite

`benchmark-results-v1.2.json` stores the latest local benchmark output.

**Important:** these numbers validate the bundled deterministic regression cases; they are not a claim of 100% real-world security accuracy.

## Run on Windows

Double-click `start.bat`, then open `http://127.0.0.1:8000`.

## Run manually

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Test / benchmark

```bash
cd backend
pytest -q
python benchmark.py
```

## Developer integration

See `docs/ONBOARDING.md`, `examples/guarded_tool_execution.py`, and `sdk/trustkernel/`.

The guarded SDK path evaluates the proposed tool call first. `BLOCK` and `REQUIRE_APPROVAL` do **not** invoke the real executor callback; a deterministic `REWRITE` exposes the repaired effective action to the callback.

## Architecture

`Workspace/API Key → Agent Identity → Intent → Provenance/Action Graph → Policy Integrity → Risk/Simulation → Repair/Approval/Block → Tool Gate → Audit + Incident + Telemetry`

Start with:
- `docs/MASTER_UPGRADE_V1_1.md`
- `docs/MASTER_UPGRADE_V1.md`
- `docs/ARCHITECTURE.md`
- `docs/STARTUP_MVP.md`
- `docs/THREAT_MODEL.md`
- `docs/EVALUATION.md`
- `docs/RESEARCH.md`
- `docs/adr/`

## Research basis

v1.2 is explicitly informed by current work around OWASP Agent Control Standard / Agentic Top 10, NIST software & AI agent identity/authorization, current MCP authorization hardening, and OpenTelemetry GenAI observability. Exact primary-source links and the resulting engineering decisions are recorded in `docs/MASTER_UPGRADE_V1_1.md` and `docs/MASTER_UPGRADE_V1.md`.

## Safety

High-risk demonstrations are local simulations. The hackathon MVP does not perform real payments, secret exfiltration, destructive production database actions, or attacks against external systems.

## v1.2 identity & governance upgrade

- Signed, expiring human member sessions with revocation and live RBAC refresh
- Ed25519 agent workload identities for replay-resistant agent-to-agent messages
- Governed policy promotion: immutable bundle → structured diff → approval-group votes → activation
- Deployment security-posture checks and HTTP hardening
- 47 automated tests passing
- 19-scenario / 190-evaluation deterministic regression suite (not production accuracy)
