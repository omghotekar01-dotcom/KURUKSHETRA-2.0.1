from __future__ import annotations

from .services.persistence import configure_store_backend

configure_store_backend()

from . import main as main_module
from .v13_api import router as v13_router
from .v14_api import router as v14_router

main_module.VERSION = "1.4.1"
app = main_module.app
app.version = "1.4.1"
app.include_router(v13_router)
app.include_router(v14_router)
