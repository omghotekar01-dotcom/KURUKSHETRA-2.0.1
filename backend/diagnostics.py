from __future__ import annotations

import importlib.util
import json
import os
import platform
import socket
import sys
from pathlib import Path


def _writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".trustkernel-write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def _port_available(host: str = "127.0.0.1", port: int = 8000) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def run() -> dict:
    backend = os.getenv("TRUSTKERNEL_DB_BACKEND", "sqlite").strip().lower() or "sqlite"
    data_dir = Path(__file__).resolve().parent / "data"
    db_path = Path(os.getenv("TRUSTKERNEL_DB_PATH", str(data_dir / "trustkernel.db"))).expanduser()

    required_modules = ["fastapi", "uvicorn", "cryptography", "jwt"]
    modules = {name: importlib.util.find_spec(name) is not None for name in required_modules}

    checks = {
        "python_3_11_plus": sys.version_info >= (3, 11),
        "required_modules": all(modules.values()),
        "data_directory_writable": _writable(db_path.parent if backend == "sqlite" else data_dir),
        "api_port_8000_available": _port_available(),
    }

    details = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "database_backend": backend,
        "database_path": str(db_path) if backend == "sqlite" else None,
        "module_checks": modules,
        "environment": os.getenv("TRUSTKERNEL_ENV", "development"),
        "offline_mode": backend == "sqlite",
    }

    passed = all(bool(value) for value in checks.values())
    return {
        "status": "ready" if passed else "failed",
        "passed": passed,
        "checks": checks,
        "details": details,
        "recovery_hint": (
            "If the demo database is damaged, run `python demo_reseed.py --yes` from backend. "
            "The reseed command intentionally refuses PostgreSQL."
        ),
    }


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["passed"] else 1)
