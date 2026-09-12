from pathlib import Path

from app.services.otlp import _resolve_native_endpoint, _runtime_version, otlp


ROOT = Path(__file__).resolve().parents[2]


def test_otlp_runtime_version_uses_canonical_repository_version():
    canonical = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    assert _runtime_version() == canonical


def test_native_endpoint_resolution_honors_signal_specific_precedence(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector.example/base")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://collector.example/custom/traces")
    assert _resolve_native_endpoint() == "https://collector.example/custom/traces"


def test_native_endpoint_resolution_appends_trace_path_to_global_endpoint(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", raising=False)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector.example/otel/")
    assert _resolve_native_endpoint() == "https://collector.example/otel/v1/traces"


def test_native_export_rejects_plain_http_in_production(monkeypatch):
    monkeypatch.setenv("TRUSTKERNEL_ENV", "production")
    result = otlp.send_native(endpoint="http://collector.internal:4318/v1/traces")

    assert result["sent"] is False
    assert result["reason"] == "otlp_https_required_in_production"
    assert result["transport"] == "otel-sdk"


def test_json_export_rejects_plain_http_in_production(monkeypatch):
    monkeypatch.setenv("TRUSTKERNEL_ENV", "production")
    result = otlp.send(endpoint="http://collector.internal:4318/v1/traces")

    assert result["sent"] is False
    assert result["reason"] == "otlp_https_required_in_production"
    assert result["transport"] == "json-http"


def test_local_demo_http_collector_remains_allowed(monkeypatch):
    monkeypatch.setenv("TRUSTKERNEL_ENV", "development")
    monkeypatch.setattr("httpx.post", lambda *args, **kwargs: type("Response", (), {"status_code": 200})())
    result = otlp.send(endpoint="http://127.0.0.1:4318/v1/traces")

    assert result["sent"] is True
    assert result["transport"] == "json-http"
