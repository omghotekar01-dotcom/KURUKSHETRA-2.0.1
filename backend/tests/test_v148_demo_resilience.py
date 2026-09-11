from __future__ import annotations

import importlib.util

import demo_reseed
import diagnostics


def test_diagnostics_reports_core_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("TRUSTKERNEL_DB_BACKEND", "sqlite")
    monkeypatch.setenv("TRUSTKERNEL_DB_PATH", str(tmp_path / "demo.db"))
    monkeypatch.setattr(diagnostics, "_port_available", lambda host="127.0.0.1", port=8000: True)
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: object())

    result = diagnostics.run()

    assert result["passed"] is True
    assert result["details"]["database_backend"] == "sqlite"
    assert result["details"]["offline_mode"] is True
    assert result["checks"]["data_directory_writable"] is True


def test_reseed_requires_explicit_confirmation(monkeypatch):
    monkeypatch.setenv("TRUSTKERNEL_DB_BACKEND", "sqlite")
    result = demo_reseed.reseed(confirm=False)
    assert result["passed"] is False
    assert result["status"] == "confirmation_required"


def test_reseed_refuses_non_sqlite_backend(monkeypatch):
    monkeypatch.setenv("TRUSTKERNEL_DB_BACKEND", "postgres")
    result = demo_reseed.reseed(confirm=True)
    assert result["passed"] is False
    assert result["status"] == "refused"
    assert "never wipe PostgreSQL" in result["reason"]
