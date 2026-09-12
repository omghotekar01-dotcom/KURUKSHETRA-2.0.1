# TrustKernel Judge Runbook

This is the shortest reliable demo path for the hackathon backup project.

## Canonical rehearsal command

Before opening the UI for a judge or before submission, run exactly this:

```bash
cd backend
python rehearsal.py
```

The rehearsal is fail-closed and runs, in order:

1. startup/environment diagnostics;
2. the full pytest regression suite;
3. the deterministic bundled benchmark regression gate; and
4. the six-scenario Judge Mode + audit-chain integrity gate.

A successful run returns top-level `"passed": true` and `"status": "ready"`.

For a faster smoke check that intentionally skips pytest:

```bash
python rehearsal.py --skip-tests --iterations 1
```

Do **not** use the smoke form as submission evidence; the full command is the canonical rehearsal gate and is also exercised by CI.

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

Both launchers create/reuse `backend/.venv`, install backend dependencies, run environment diagnostics, run `backend/judge_check.py`, and start TrustKernel only when every local demo gate passes.

Open `http://127.0.0.1:8000` after the server starts.

## Startup diagnostics

Run diagnostics independently with:

```bash
cd backend
python diagnostics.py
```

The command checks the supported Python runtime, required modules, writable demo storage, database mode, and whether the default judge port can be bound. It does not print secrets.

If port 8000 is occupied, stop the process using that port before starting the judge launcher.

## What the judge preflight proves

The preflight verifies:

- the configured persistence backend answers a health probe;
- the six-scenario Judge Mode executes;
- the Judge Mode contract identifier is intact;
- all six judge scenarios are present; and
- the audit chain remains valid after the sequence.

A failed diagnostic or preflight exits non-zero and prevents the launcher from presenting a broken demo as healthy.

## Re-run only the Judge Mode preflight

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

## Production-profile validation

Production readiness stays a separate gate because the judge/offline rehearsal intentionally uses the SQLite-first development profile while production requires stronger configuration such as PostgreSQL and external identity settings.

With the required production environment configured, run:

```bash
cd backend
python deployment_check.py
```

The production readiness command is expected to fail closed when mandatory controls are absent or unsafe values are configured.

## Demo order

1. Open the command-center UI.
2. Explain that TrustKernel sits between an AI agent and real tools, authorizing actions before execution.
3. Run the six-scenario Judge Mode to show ALLOW / REWRITE / REQUIRE_APPROVAL / BLOCK behavior.
4. Open Policy Studio and show the diff + four-eyes approval path.
5. Open Incident Causal Explorer and walk the action chain, finding, remediation, and audit evidence.
6. Show workload identity / MCP governance / runtime telemetry only if the judge asks for implementation depth.

## Guarded demo reset / reseed

The default hackathon mode is SQLite and intentionally works offline. To reset a damaged or heavily-used local demo state, stop TrustKernel and run:

```bash
cd backend
python demo_reseed.py --yes
```

The command:

- operates only when `TRUSTKERNEL_DB_BACKEND` is SQLite;
- creates a timestamped backup of the existing SQLite database when one exists;
- removes SQLite WAL/SHM sidecars together with the database;
- initializes a clean schema;
- deterministically executes the six Judge Mode scenarios; and
- verifies the resulting audit chain.

It deliberately refuses PostgreSQL. Never use a judge-demo reset procedure against production persistence.

## Demo disaster recovery

If the internet or external identity provider is unavailable, use the default local SQLite + local/demo identity path and explain that OIDC support is an optional production integration. The core runtime, Judge Mode, Policy Studio data, incident evidence, audit chain, and bundled regression benchmark are designed to remain demonstrable offline.

If PostgreSQL is unavailable during a hackathon demo, do not modify the production profile. Restart the judge demo with the default SQLite environment and rerun `python rehearsal.py`.

If local demo state is corrupted, use the guarded reseed command above, then rerun `python rehearsal.py` before reopening the UI.

If the default API port is occupied, free port 8000 and rerun the rehearsal rather than changing ports during the live demo unless absolutely necessary.

## Claims discipline

The bundled benchmark and Judge Mode are deterministic regression/evaluation evidence. They must never be presented as production security accuracy, certification, exploit coverage, or a guarantee that TrustKernel blocks every real-world attack.
