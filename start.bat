@echo off
setlocal
cd /d "%~dp0backend"

if not exist .venv (
  py -m venv .venv
  if errorlevel 1 exit /b 1
)

call .venv\Scripts\activate
python -m pip install -r requirements.txt
if errorlevel 1 exit /b 1

echo.
echo [TrustKernel] Running environment diagnostics...
python diagnostics.py
if errorlevel 1 (
  echo [TrustKernel] Diagnostics failed. Server will not start.
  echo [TrustKernel] See docs\JUDGE_RUNBOOK.md for the recovery path.
  exit /b 1
)

echo.
echo [TrustKernel] Running judge preflight...
python judge_check.py
if errorlevel 1 (
  echo [TrustKernel] Preflight failed. Server will not start.
  echo [TrustKernel] To reset only the offline SQLite demo: cd backend ^&^& python demo_reseed.py --yes
  exit /b 1
)

echo.
echo [TrustKernel] Diagnostics and preflight passed. Starting http://127.0.0.1:8000
python -m uvicorn app.bootstrap:app --host 127.0.0.1 --port 8000
endlocal
