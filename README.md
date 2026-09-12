# TrustKernel

**Runtime Security & Authorization Control Plane for Autonomous AI Agents**  
Kurukshetra 2.0 · Open Innovation backup project · Startup MVP v1.4.22

TrustKernel sits on the execution path between autonomous AI agents and their tools. It evaluates identity, workspace scope, intent, tool provenance, information-flow labels, policy, risk and consequences **before execution**, returning deterministic `ALLOW`, `ALLOW_WITH_LOG`, `REWRITE`, `REQUIRE_APPROVAL`, or `BLOCK` outcomes.

## What is implemented

- Standards-based OIDC/JWT identity, signed sessions, workspace RBAC and configurable external-role mapping.
- Governed policy and MCP registry changes with four-eyes approval and signed evidence envelopes.
- Workload attestation metadata plus KMS/HSM/SPIFFE-style signing **and verification** adapters. Workload signature envelope v2 binds purpose, time window, nonce, message/attestation digests, external key reference and algorithm; envelope lifetime is bounded and verification fails closed on tampering, expiry, identity mismatch or replay-context rejection.
- Runtime action graph, taint/provenance tracking, deterministic policy/risk evaluation, safe-plan repair, incidents and audit evidence.
- SQLite offline mode plus PostgreSQL persistence with checksum-pinned migrations, advisory-lock coordination and live PostgreSQL CI.
- **First-party Redis distributed quota backend** using atomic Lua read/decide/write, Redis server time, cluster-safe workspace keys, bounded client timeouts and fail-closed startup. In-memory quota enforcement remains the offline/demo default.
- Native OpenTelemetry exporter option with canonical runtime version binding, standard OTLP endpoint precedence and HTTPS enforcement for configured production export.
- **Judge-facing governance review UI** with signed policy-bundle semantic diff triage, security-sensitive change filtering, governance-stage visualization, incident blast-radius metrics, causal action graphs, safe-repair context and remediation/evidence timelines.
- **AgentDojo-inspired benchmark importer/report v3** with suite/model/attack/defense/task/trace provenance, malformed-record rejection, SHA-256 evidence digests, Wilson confidence intervals, coverage breakdowns, and an explicit boundary preventing TrustKernel decision rates from being mislabeled as native AgentDojo utility or targeted ASR.
- **Package-validated Python SDK** with PEP 517 wheel/sdist builds, `twine check`, installed-wheel import/version/`py.typed` smoke validation, and guarded execution examples.
- Non-root container runtime, production deployment-readiness gate, deterministic release manifest, SBOM/vulnerability CI and GitHub provenance attestations.
- Six-scenario Judge Mode plus a unified rehearsal command.

## Run locally

Windows:

```powershell
.\start.bat
```

Linux/macOS:

```bash
chmod +x start.sh
./start.sh
```

Open `http://127.0.0.1:8000`.

## Canonical validation

```bash
cd backend
python rehearsal.py
python deployment_check.py
```

CI additionally runs live PostgreSQL and Redis integration tests plus a release-style SDK wheel/sdist build-and-install smoke gate.

Production quota configuration uses:

```text
TRUSTKERNEL_QUOTA_BACKEND=redis
TRUSTKERNEL_REDIS_URL=rediss://redis.example:6379/0
```

`rediss://` is required by the production-readiness gate; local/offline development continues to default to the in-memory backend.

Production telemetry should use either the trace-specific OTLP endpoint or the standard global OTLP endpoint over HTTPS:

```text
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://otel-collector.example/v1/traces
# or
OTEL_EXPORTER_OTLP_ENDPOINT=https://otel-collector.example
```

For the global endpoint, TrustKernel follows the OTLP/HTTP convention and appends `/v1/traces`. Plain HTTP collectors remain supported for local/demo use, but configured plaintext OTLP export is rejected when `TRUSTKERNEL_ENV=production`.

## Python SDK

```bash
python -m pip install ./sdk
python examples/sdk_guard_quickstart.py
```

Release-style package validation:

```bash
cd sdk
python -m pip install "build>=1.2,<2" "twine>=6,<7"
python -m build
python -m twine check dist/*
```

## Branch workflow

- `main` — stable, runnable, submission-ready checkpoints only.
- `trustkernel-dev` — active integration.

Changes are developed on `trustkernel-dev`, validated in CI, proposed to `main` by pull request, and merged only when the checkpoint is green.

## Evidence boundary

**Claims discipline:** bundled/synthetic/imported benchmark and Judge Mode results are deterministic regression/evaluation evidence. They are **not** production security accuracy, certification, universal exploit coverage, or a guarantee that every real-world attack will be blocked. TrustKernel benchmark reports also do not infer native AgentDojo utility or targeted ASR from policy decisions. Artifact provenance proves origin/integrity claims about the attested build evidence; it does not prove that the software is secure.

Judge-facing material lives in `docs/JUDGE_RUNBOOK.md`, `docs/JUDGE_CHEATSHEET.md`, `docs/JUDGE_ARCHITECTURE.md`, and `docs/HACKATHON_PITCH.md`.
