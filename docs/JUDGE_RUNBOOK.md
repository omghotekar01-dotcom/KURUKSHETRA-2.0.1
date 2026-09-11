# TrustKernel Judge Runbook

This is the shortest reliable demo path for the hackathon backup project.

## One-command startup

### Windows

Double-click `start.bat` or run:

```powershell
.\start.bat
```

### Linux / macOS

```bash
chmod +x start.sh
./start.sh
```

Both launchers create/reuse `backend/.venv`, install the pinned backend dependencies, run `backend/judge_check.py`, and start TrustKernel only when the deterministic preflight passes.

Open `http://127.0.0.1:8000` after the server starts.

## What the preflight proves

The preflight verifies:

- the configured persistence backend answers a health probe;
- the six-scenario Judge Mode executes;
- the Judge Mode contract identifier is intact;
- all six judge scenarios are present; and
- the audit chain remains valid after the sequence.

A failed preflight exits non-zero and prevents the launcher from presenting a broken demo as healthy.

## Re-run the preflight without starting the server

```bash
cd backend
python judge_check.py
```

Expected top-level result:

```json
{
  "passed": true,
  "status": "ready"
}
```

## Full rehearsal gate

Before submission or a judge rehearsal, run:

```bash
cd backend
pytest -q
python benchmark.py
python judge_check.py
```

For a production-profile configuration, also run:

```bash
python deployment_check.py
```

The production readiness command is expected to fail closed when mandatory production controls are missing.

## Demo order

1. Open the command-center UI.
2. Explain that TrustKernel sits between an AI agent and real tools, authorizing actions before execution.
3. Run the six-scenario Judge Mode to show ALLOW / REWRITE / REQUIRE_APPROVAL / BLOCK behavior.
4. Open Policy Studio and show the diff + four-eyes approval path.
5. Open Incident Causal Explorer and walk the action chain, finding, remediation, and audit evidence.
6. Show workload identity / MCP governance / runtime telemetry only if the judge asks for implementation depth.

## Reset guidance

The default hackathon mode is SQLite and is intentionally offline-friendly. If a completely fresh local demo state is required, stop TrustKernel, back up `backend/data/trustkernel.db`, then remove that local database and restart. Do not delete a production PostgreSQL database to reset a demo.

## Claims discipline

The bundled benchmark and Judge Mode are deterministic regression/evaluation evidence. They must never be presented as production security accuracy, certification, exploit coverage, or a guarantee that TrustKernel blocks every real-world attack.
