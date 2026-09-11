#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT_DIR/backend"

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi

. .venv/bin/activate
python -m pip install -r requirements.txt

echo ""
echo "[TrustKernel] Running judge preflight..."
python judge_check.py

echo ""
echo "[TrustKernel] Preflight passed. Starting http://127.0.0.1:8000"
exec python -m uvicorn app.bootstrap:app --host 127.0.0.1 --port 8000
