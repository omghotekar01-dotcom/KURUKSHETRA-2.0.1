# TrustKernel

**Runtime Security & Authorization Control Plane for Autonomous AI Agents**  
Kurukshetra 2.0 · Open Innovation backup project · Startup MVP v1.4.x

TrustKernel sits on the execution path between autonomous AI agents and their tools. It evaluates identity, workspace scope, intent, tool provenance, information-flow labels, policy, risk and consequences **before execution**, then returns one of five deterministic outcomes:

`ALLOW · ALLOW_WITH_LOG · REWRITE · REQUIRE_APPROVAL · BLOCK`

It is not positioned as a prompt filter. TrustKernel is a runtime authorization, least-privilege, governance, incident-evidence and observability layer for agentic systems.

## Current capabilities

- OIDC/JWT human identity with issuer/audience/JWKS verification, discovery hardening, bounded clock skew and configurable claim/role mapping
- Signed local sessions and workspace RBAC
- Four-eyes governed policy changes with self-approval prevention
- Ed25519 workload identity, key rotation, attestation metadata and external KMS/HSM/SPIFFE-style signer adapters
- Replay-resistant inter-agent messaging
- Governed MCP trust registry with signed change evidence, resource/scope/token-passthrough enforcement
- Runtime action graph, taint/provenance tracking, policy evaluation, risk analysis and deterministic safe-plan repair
- Persistent incidents, approvals, audit ledger and remediation evidence
- SQLite offline mode plus PostgreSQL persistence abstraction and schema migrations
- Distributed quota backend interface
- OTLP JSON/HTTP telemetry plus optional native OpenTelemetry SDK exporter
- Visual Policy Studio with structured diff/approval flow
- Incident Causal Explorer with remediation timeline
- Security + utility benchmark bridge with FPR/FNR and stronger AgentDojo-style dataset provenance/reporting
- Packageable Python guard SDK with lightweight LangChain/LangGraph/AutoGen/MCP integration guards
- Six-scenario Judge Mode
- Non-root Docker runtime, production Compose profile and machine-checkable deployment-readiness gate

## One-command judge startup

### Windows

```powershell
.\start.bat
```

### Linux / macOS

```bash
chmod +x start.sh
./start.sh
```

Both launchers create/reuse the backend virtual environment, install dependencies, run the deterministic Judge preflight, and start the server only when that preflight passes.

Open `http://127.0.0.1:8000`.

For the exact hackathon rehearsal path, use [`docs/JUDGE_RUNBOOK.md`](docs/JUDGE_RUNBOOK.md).

## Manual development run

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python judge_check.py
uvicorn app.bootstrap:app --reload
```

## Validation gates

```bash
cd backend
pytest -q
python benchmark.py
python judge_check.py
```

Production-profile configurations can additionally run:

```bash
python deployment_check.py
```

CI runs the full tests, deterministic regression benchmark, Judge Mode preflight and production deployment-readiness gate before stable checkpoints are merged to `main`.

**Claims discipline:** bundled/synthetic/imported benchmark and Judge Mode results are deterministic regression/evaluation evidence. They are **not** production security accuracy, certification, universal exploit coverage, or a guarantee that every real-world attack will be blocked.

## Branch workflow

- `main` — stable, runnable, submission-ready checkpoints only
- `trustkernel-dev` — active integration

Changes are developed on `trustkernel-dev`, validated by CI, proposed to `main` by pull request, and merged only when the checkpoint is green.

## Architecture

`Human / Workload Identity → Workspace & Agent IAM → Intent → Provenance & Action Graph → Policy / MCP Governance → Risk & Consequence Analysis → ALLOW / REWRITE / APPROVAL / BLOCK → Audit + Incident + Telemetry`

Useful docs:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/JUDGE_RUNBOOK.md`](docs/JUDGE_RUNBOOK.md)
- [`docs/HACKATHON_PITCH.md`](docs/HACKATHON_PITCH.md)
- [`docs/JUDGE_QA.md`](docs/JUDGE_QA.md)
- [`docs/PRODUCTION_PROFILE.md`](docs/PRODUCTION_PROFILE.md)
- [`docs/EVALUATION.md`](docs/EVALUATION.md)
- [`docs/ONBOARDING.md`](docs/ONBOARDING.md)

## Safety

High-risk demonstrations are local simulations. The hackathon MVP does not perform real payments, secret exfiltration, destructive production database actions, or attacks against external systems.
