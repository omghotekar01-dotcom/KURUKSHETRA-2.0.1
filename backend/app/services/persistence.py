from __future__ import annotations

import os
from typing import Any


def configure_store_backend() -> Any:
    """Select persistence before service modules capture the storage singleton.

    SQLite remains the zero-config offline default. PostgreSQL is opt-in with
    TRUSTKERNEL_DB_BACKEND=postgres and TRUSTKERNEL_DATABASE_URL.
    """
    from . import storage

    backend = os.getenv("TRUSTKERNEL_DB_BACKEND", "sqlite").strip().lower()
    if backend in {"", "sqlite"}:
        return storage.store
    if backend not in {"postgres", "postgresql"}:
        raise RuntimeError(f"unsupported TRUSTKERNEL_DB_BACKEND: {backend}")

    from .postgres_storage import PostgresStore

    if isinstance(storage.store, PostgresStore):
        return storage.store
    storage.store = PostgresStore()
    return storage.store


def persistence_status() -> dict[str, str]:
    from . import storage

    active = storage.store
    backend = getattr(active, "backend", "sqlite")
    return {
        "backend": str(backend),
        "mode": "offline" if str(backend) == "sqlite" else "production",
    }
