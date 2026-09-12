from __future__ import annotations

from pathlib import Path

from .services.persistence import configure_store_backend
from .services.quotas import configure_quota_backend

configure_store_backend()
configure_quota_backend()

from . import main as main_module
from .v13_api import router as v13_router
from .v14_api import router as v14_router

ROOT = Path(__file__).resolve().parents[2]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

main_module.VERSION = VERSION
app = main_module.app
app.version = VERSION
app.include_router(v13_router)
app.include_router(v14_router)


@app.get("/api/version", tags=["release"])
def release_version() -> dict:
    return {
        "schema": "trustkernel.release-version.v1",
        "version": VERSION,
        "source": "VERSION",
    }
