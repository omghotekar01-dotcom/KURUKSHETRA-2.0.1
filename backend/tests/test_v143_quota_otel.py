from app.services.quotas import CallbackQuotaBackend, InMemoryQuotaBackend, QuotaService
from app.services.otlp import otlp
from app.services.telemetry import telemetry


def test_in_memory_quota_backend_preserves_offline_behavior(monkeypatch):
    monkeypatch.setenv("TRUSTKERNEL_RATE_LIMIT_PER_MINUTE", "2")
    monkeypatch.setenv("TRUSTKERNEL_DAILY_ACTION_QUOTA", "5")
    service = QuotaService(InMemoryQuotaBackend())

    first = service.check_and_consume("ws", now=1000.0)
    second = service.check_and_consume("ws", now=1001.0)
    blocked = service.check_and_consume("ws", now=1002.0)

    assert first["allowed"] is True
    assert second["allowed"] is True
    assert blocked["allowed"] is False
    assert blocked["reason"] == "minute_rate_limit"
    assert blocked["backend"] == "memory"
    assert blocked["distributed"] is False


def test_callback_quota_backend_supports_distributed_atomic_adapter(monkeypatch):
    monkeypatch.setenv("TRUSTKERNEL_RATE_LIMIT_PER_MINUTE", "3")
    monkeypatch.setenv("TRUSTKERNEL_DAILY_ACTION_QUOTA", "8")
    calls = []

    def consume(workspace_id, limits, now):
        calls.append(("consume", workspace_id, limits.per_minute, limits.per_day, now))
        return {
            "allowed": True,
            "reason": "ok",
            "minute_used": 1,
            "minute_limit": limits.per_minute,
            "day_used": 1,
            "day_limit": limits.per_day,
        }

    def inspect(workspace_id, limits, now):
        calls.append(("inspect", workspace_id, limits.per_minute, limits.per_day, now))
        return {
            "minute_used": 1,
            "minute_limit": limits.per_minute,
            "day_used": 1,
            "day_limit": limits.per_day,
        }

    def clear(workspace_id):
        calls.append(("clear", workspace_id))

    service = QuotaService(CallbackQuotaBackend(consume=consume, inspect=inspect, clear=clear, name="redis-atomic"))
    decision = service.check_and_consume("ws_dist", now=2000.0)
    status = service.status("ws_dist", now=2001.0)
    service.reset("ws_dist")

    assert decision["allowed"] is True
    assert decision["backend"] == "redis-atomic"
    assert decision["distributed"] is True
    assert status["backend"] == "redis-atomic"
    assert calls[0] == ("consume", "ws_dist", 3, 8, 2000.0)
    assert calls[-1] == ("clear", "ws_dist")


def test_native_otel_exporter_path(monkeypatch):
    monkeypatch.delenv("TRUSTKERNEL_OTLP_BEARER_TOKEN", raising=False)
    telemetry.emit(
        "trustkernel.v143.native_otel",
        workspace_id="ws_otel_native",
        agent_id="agent_otel_native",
        attributes={"trustkernel.decision": "ALLOW", "trustkernel.risk_score": 7},
    )

    exported = {"batches": 0, "spans": 0}

    class DummyExporter:
        def __init__(self, endpoint=None, headers=None, timeout=None):
            exported["endpoint"] = endpoint

        def export(self, spans):
            from opentelemetry.sdk.trace.export import SpanExportResult
            exported["batches"] += 1
            exported["spans"] += len(spans)
            return SpanExportResult.SUCCESS

        def shutdown(self):
            return None

        def force_flush(self, timeout_millis=30000):
            return True

    monkeypatch.setattr(
        "opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter",
        DummyExporter,
    )
    result = otlp.send_native(
        "ws_otel_native",
        endpoint="http://collector.test/v1/traces",
        timeout=1.0,
    )

    assert result["sent"] is True
    assert result["transport"] == "otel-sdk"
    assert result["spans"] >= 1
    assert exported["endpoint"] == "http://collector.test/v1/traces"
    assert exported["spans"] >= 1
