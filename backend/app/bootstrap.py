from __future__ import annotations

from . import main as main_module
from .v13_api import router as v13_router

main_module.VERSION = "1.3.0"
app = main_module.app
app.version = "1.3.0"
app.include_router(v13_router)
