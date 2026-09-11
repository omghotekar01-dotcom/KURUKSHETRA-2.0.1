from __future__ import annotations

import argparse
import json
import os
import shutil
import time
from pathlib import Path


def _sqlite_path() -> Path:
    configured = os.getenv("TRUSTKERNEL_DB_PATH")
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path(__file__).resolve().parent / "data" / "trustkernel.db").resolve()


def _backup_existing(path: Path) -> str | None:
    if not path.exists():
        return None
    backup = path.with_name(f"{path.name}.backup-{int(time.time())}")
    shutil.copy2(path, backup)
    return str(backup)


def _remove_sqlite_files(path: Path) -> None:
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        candidate.unlink(missing_ok=True)


def reseed(confirm: bool = False) -> dict:
    backend = os.getenv("TRUSTKERNEL_DB_BACKEND", "sqlite").strip().lower() or "sqlite"
    if backend != "sqlite":
        return {
            "status": "refused",
            "passed": False,
            "reason": "Demo reseed only supports the offline SQLite backend and will never wipe PostgreSQL.",
            "database_backend": backend,
        }
    if not confirm:
        return {
            "status": "confirmation_required",
            "passed": False,
            "reason": "Pass --yes to reset and deterministically reseed the local demo database.",
        }

    path = _sqlite_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = _backup_existing(path)
    _remove_sqlite_files(path)

    # Import only after the old DB has been removed so the singleton initializes
    # against a clean SQLite file.
    from app.services.audit import ledger
    from app.services.storage import store
    from app.v13_api import judge_demo_v13

    if not store.ping():
        return {"status": "failed", "passed": False, "reason": "Fresh SQLite store failed health check."}

    judge = judge_demo_v13()
    sequence = judge.get("sequence", [])
    audit = ledger.verify()
    passed = len(sequence) == 6 and audit.get("valid") is True
    return {
        "status": "ready" if passed else "failed",
        "passed": passed,
        "database_backend": "sqlite",
        "database_path": str(path),
        "backup_path": backup,
        "seeded_scenarios": len(sequence),
        "audit_chain_valid": audit.get("valid") is True,
        "note": "Judge scenarios are deterministic demo/regression evidence, not production security accuracy.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Reset and reseed TrustKernel's offline judge-demo SQLite state.")
    parser.add_argument("--yes", action="store_true", help="Confirm destructive reset of the local SQLite demo database.")
    args = parser.parse_args()
    result = reseed(confirm=args.yes)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
