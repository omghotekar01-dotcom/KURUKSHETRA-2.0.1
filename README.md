# TrustKernel

**Runtime Security & Authorization Control Plane for Autonomous AI Agents**  
Kurukshetra 2.0 · Open Innovation backup project · Startup MVP v1.4.16

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
- SQLite offline mode plus PostgreSQL persistence abstraction, checksum-pinned schema migrations, transaction-scoped migration ownership and live PostgreSQL CI coverage
- Distributed quota backend interface
- OTLP JSON/HTTP telemetry plus optional native OpenTelemetry SDK exporter
- Visual Policy Studio with structured diff/approval flow
- Incident Causal Explorer with remediation timeline
- Security + utility benchmark bridge with FPR/FNR and stronger AgentDojo-style dataset provenance/reporting
- Packageable Python guard SDK with lightweight LangChain/LangGraph/AutoGen/MCP integration guards
- Six-scenario Judge Mode
- Non-root Docker runtime, production Compose profile and machine-checkable deployment-readiness gate
- Unified fail-closed judge rehearsal, release-integrity gate, guarded offline demo reseed and startup diagnostics
- Deterministic SHA-256 submission manifest for byte-level identity of critical release assets
- Supply-chain assurance with exact direct-dependency pins, blocking CI vulnerability auditing, CycloneDX SBOM evidence, and supplementary GitHub dependency review when the repository Dependency graph feature is available
- GitHub OIDC-backed artifact attestations for the stable `main` submission manifest plus its CycloneDX SBOM relationship, enabling provenance/integrity verification without claiming that provenance itself proves the software is secure
- Canonical release-version binding from the repository `VERSION` file into FastAPI runtime metadata, with release-gate protection against stale runtime or judge-UI version literals

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

For the exact hackathon rehearsal path, use [`docs/JUDGE_RUNBOOK.md`](docs/JUDGE_RUNBOOK.md). For the shortest judge-facing talking points, use [`docs/JUDGE_CHEATSHEET.md`](docs/JUDGE_CHEATSHEET.md).

## Canonical rehearsal

Before a judge demo or submission checkpoint, run the same fail-closed coordinator used by CI:

```bash
cd backend
python rehearsal.py
```

This coordinates startup diagnostics, release/submission integrity, the full pytest suite, deterministic benchmark regression checks, Judge Mode and audit-chain verification. Production-profile configuration additionally runs `deployment_check.py` in CI.

To print a deterministic machine-readable manifest of submission-critical assets:

```bash
cd backend
python submission_manifest.py
```

The manifest records the canonical version, file sizes and SHA-256 digests for critical release assets. It proves byte-level identity for those listed files only; it is not a security certification.

On stable `main` pushes, the supply-chain workflow also submits this manifest to GitHub's artifact-attestation service and binds the generated CycloneDX SBOM to the same subject. Consumers can verify provenance with GitHub's attestation tooling. The attestation establishes origin/integrity claims about the artifact and workflow; it does **not** establish that the software is vulnerability-free or production-secure.

The running API exposes the same canonical release version at `GET /api/version`; FastAPI metadata is bound to that value by `app.bootstrap` instead of an independently hard-coded release string.

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
python supply_chain_check.py
python release_check.py
python submission_manifest.py
python benchmark.py
python judge_check.py
python rehearsal.py
```

Production-profile configurations can additionally run:

```bash
python deployment_check.py
```

CI runs a live PostgreSQL persistence integration test before the unified rehearsal and production deployment-readiness gate. The live database test verifies the migration ledger and representative workspace, agent and approval CRUD through the production adapter. The separate supply-chain workflow also runs blocking `pip-audit` known-vulnerability scanning and emits CycloneDX JSON SBOM + submission-manifest build evidence. On stable `main` pushes, GitHub OIDC-backed attestations are requested for the submission manifest and its SBOM relationship. On pull requests the workflow additionally attempts GitHub's native dependency-review action; that supplementary check requires the repository Dependency graph feature and is non-blocking when GitHub reports the feature unavailable. The offline `supply_chain_check.py` validates declaration hygiene; vulnerability findings come from the CI audit and can change as advisory databases evolve.

**Claims discipline:** bundled/synthetic/imported benchmark and Judge Mode results are deterministic regression/evaluation evidence. They are **not** production security accuracy, certification, universal exploit coverage, or a guarantee that every real-world attack will be blocked.

## Python SDK

```bash
python -m pip install ./sdk
python examples/sdk_guard_quickstart.py
```

Use `TrustKernelClient.execute_guarded(...)` to make the authorization decision before invoking the real tool executor. See [`sdk/README.md`](sdk/README.md).

## Branch workflow

- `main` — stable, runnable, submission-ready checkpoints only
- `trustkernel-dev` — active integration

Changes are developed on `trustkernel-dev`, validated by CI, proposed to `main` by pull request, and merged only when the checkpoint is green.

## Architecture

`Human / Workload Identity → Workspace & Agent IAM → Intent → Provenance & Action Graph → Policy / MCP Governance → Risk & Consequence Analysis → ALLOW / REWRITE / APPROVAL / BLOCK → Audit + Incident + Telemetry`

Useful docs:

- [`docs/JUDGE_CHEATSHEET.md`](docs/JUDGE_CHEATSHEET.md)
- [`docs/JUDGE_ARCHITECTURE.md`](docs/JUDGE_ARCHITECTURE.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/JUDGE_RUNBOOK.md`](docs/JUDGE_RUNBOOK.md)
- [`docs/HACKATHON_PITCH.md`](docs/HACKATHON_PITCH.md)
- [`docs/JUDGE_QA.md`](docs/JUDGE_QA.md)
- [`docs/PRODUCTION_PROFILE.md`](docs/PRODUCTION_PROFILE.md)
- [`docs/EVALUATION.md`](docs/EVALUATION.md)
- [`docs/ONBOARDING.md`](docs/ONBOARDING.md)

## Safety

High-risk demonstrations are local simulations. The hackathon MVP does not perform real payments, secret exfiltration, destructive production database actions, or attacks against external systems.