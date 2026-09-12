from app.services.otlp import _resolve_native_endpoint


def test_native_endpoint_resolution_honors_signal_specific_precedence(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector.example/base")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://collector.example/custom/traces")
    assert _resolve_native_endpoint() == "https://collector.example/custom/traces"


def test_native_endpoint_resolution_appends_trace_path_to_global_endpoint(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", raising=False)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector.example/otel/")
    assert _resolve_native_endpoint() == "https://collector.example/otel/v1/traces"
