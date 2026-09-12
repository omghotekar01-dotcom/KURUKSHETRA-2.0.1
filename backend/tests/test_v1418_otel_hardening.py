from pathlib import Path

from app.services.otlp import _resolve_native_endpoint, otlp
from app.services.telemetry import telemetry


ROOT = Path(__file__).resolve().parents[2]


def _resource_attribute(payload: dict, key: str) -> str | None:
    attributes = payload["resourceSpans"][0]["resource"]["attributes"]
    for attribute in attributes:
        if attribute["key"] == key:
            return attribute["value"].get("stringValue")
    return None


def test_otlp_payload_uses_canonical_repository_version():
    telemetry.emit("trustkernel.v1418.version", workspace_id="ws_v1418")
    payload = otlp.export_json("ws_v1418")
    canonical = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

    assert _resource_attribute(payload, "service.version") == canonical
    assert payload["resourceSpans"][0]["scopeSpans"][0]["scope"]["version"] == canonical


def test_native_endpoint_resolution_honors_signal_specific_precedence(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector.example/base")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://collector.example/custom/traces")
    assert _resolve_native_endpoint() == "https://collector.example/custom/traces"


def test_native_endpoint_resolution_appends_trace_path_to_global_endpoint(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", raising=False)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector.example/otel/")
    assert _resolve_native_endpoint() == "https://collector.example/otel/v1/traces"
