import os
import tempfile
from pathlib import Path

_test_db = Path(tempfile.gettempdir()) / "trustkernel-pytest.db"
for suffix in ["", "-wal", "-shm"]:
    try:
        Path(str(_test_db) + suffix).unlink()
    except FileNotFoundError:
        pass
os.environ["TRUSTKERNEL_DB_PATH"] = str(_test_db)

import sys
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))
