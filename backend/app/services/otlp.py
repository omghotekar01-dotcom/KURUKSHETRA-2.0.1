from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import httpx

from .storage import store


class OTLPAdapter:
    """OTLP export facade with dependency-light and native SDK paths.

    export_json()/send() preserve the existing offline-friendly OTLP/HTTP JSON
    bridge. send_native() uses the official OpenTelemetry Python SDK/exporter
    when deployments want native SDK semantics and Collector interoperability.
    """

    def export_json(self, workspace_id: Optional[str] = None, limit: int = 500) -> Dict[str, Any]:
        events = store.telemetry(workspace_id, max(1, min(limit, 2000)))
        spans: List[Dict[str, Any]] = []
        for index, event in enumerate(events):
            attrs = []
            attributes = dict(event.get("attributes", {}))
            if event.get("workspace_id"):
                attributes.setdefault("trustkernel.workspace.id", event["workspace_id"])
            if event.get("agent_id"):
                attributes.setdefault("gen_ai.agent.id", event["agent_id"])
            for key, value in attributes.items():
                if value is None:
                    continue
                if isinstance(value, bool):
                    wrapped = {"boolValue": value}
                elif isinstance(value, int):
                    wrapped = {"intValue": str(value)}
                elif isinstance(value, float):
                    wrapped = {"doubleValue": value}
                else:
                    wrapped = {"stringValue": str(value)}
                attrs.append({"key": key, "value": wrapped})
            spans.append({
                "traceId": f"{index+1:032x}",
                "spanId": f"{index+1:016x}",
                "name": event["event_name"],
                "kind": 1,
                "startTimeUnixNano": str(int(event["timestamp"] * 1_000_000_000)),
                "endTimeUnixNano": str(int(event["timestamp"] * 1_000_000_000)),
                "attributes": attrs,
            })
        return {
            "resourceSpans": [{
                "resource": {"attributes": [
                    {"key": "service.name", "value": {"stringValue": "trustkernel"}},
                    {"key": "service.version", "value": {"stringValue": "1.4.3"}},
                ]},
                "scopeSpans": [{"scope": {"name": "trustkernel.security", "version": "1.4.3"}, "spans": spans}],
            }],
        }

    def send(
        self,
        workspace_id: Optional[str] = None,
        *,
        endpoint: Optional[str] = None,
        limit: int = 500,
        timeout: float = 5.0,
    ) -> Dict[str, Any]:
        target = (endpoint or os.getenv("TRUSTKERNEL_OTLP_HTTP_ENDPOINT", "")).strip()
        if not target:
            return {"sent": False, "reason": "otlp_endpoint_not_configured", "spans": 0, "transport": "json-http"}
        headers = {"Content-Type": "application/json"}
        bearer = os.getenv("TRUSTKERNEL_OTLP_BEARER_TOKEN", "").strip()
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        payload = self.export_json(workspace_id, limit)
        span_count = sum(len(scope.get("spans", [])) for resource in payload.get("resourceSpans", []) for scope in resource.get("scopeSpans", []))
        try:
            response = httpx.post(target, json=payload, headers=headers, timeout=timeout, follow_redirects=False)
            return {
                "sent": 200 <= response.status_code < 300,
                "status_code": response.status_code,
                "spans": span_count,
                "endpoint": target,
                "transport": "json-http",
            }
        except httpx.HTTPError as exc:
            return {
                "sent": False,
                "reason": "otlp_transport_error",
                "error": str(exc),
                "spans": span_count,
                "endpoint": target,
                "transport": "json-http",
            }

    def send_native(
        self,
        workspace_id: Optional[str] = None,
        *,
        endpoint: Optional[str] = None,
        limit: int = 500,
        timeout: float = 5.0,
    ) -> Dict[str, Any]:
        """Export stored TrustKernel events using the official OTel Python SDK.

        The SDK path is opt-in and does not replace the deterministic JSON path.
        A successful return means the SDK force-flush completed; Collector-side
        ingestion/retention remains an external operational concern.
        """
        target = (
            endpoint
            or os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
            or os.getenv("TRUSTKERNEL_OTLP_HTTP_ENDPOINT", "")
        ).strip()
        if not target:
            return {"sent": False, "reason": "otlp_endpoint_not_configured", "spans": 0, "transport": "otel-sdk"}

        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        except ImportError as exc:
            return {
                "sent": False,
                "reason": "opentelemetry_sdk_not_installed",
                "error": str(exc),
                "spans": 0,
                "transport": "otel-sdk",
            }

        events = store.telemetry(workspace_id, max(1, min(limit, 2000)))
        headers: Dict[str, str] = {}
        bearer = os.getenv("TRUSTKERNEL_OTLP_BEARER_TOKEN", "").strip()
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"

        exporter = OTLPSpanExporter(endpoint=target, headers=headers or None, timeout=timeout)
        provider = TracerProvider(resource=Resource.create({
            "service.name": "trustkernel",
            "service.version": "1.4.3",
        }))
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = provider.get_tracer("trustkernel.security", "1.4.3")

        emitted = 0
        try:
            for event in events:
                attributes = dict(event.get("attributes", {}))
                if event.get("workspace_id"):
                    attributes.setdefault("trustkernel.workspace.id", event["workspace_id"])
                if event.get("agent_id"):
                    attributes.setdefault("gen_ai.agent.id", event["agent_id"])
                clean_attributes = {
                    str(key): value if isinstance(value, (str, bool, int, float)) else str(value)
                    for key, value in attributes.items()
                    if value is not None
                }
                timestamp_ns = int(float(event["timestamp"]) * 1_000_000_000)
                span = tracer.start_span(str(event["event_name"]), start_time=timestamp_ns, attributes=clean_attributes)
                span.end(end_time=timestamp_ns)
                emitted += 1
            flushed = bool(provider.force_flush(timeout_millis=max(1, int(timeout * 1000))))
            return {
                "sent": flushed,
                "reason": "ok" if flushed else "otel_force_flush_failed",
                "spans": emitted,
                "endpoint": target,
                "transport": "otel-sdk",
            }
        except Exception as exc:
            return {
                "sent": False,
                "reason": "otel_sdk_export_error",
                "error": str(exc),
                "spans": emitted,
                "endpoint": target,
                "transport": "otel-sdk",
            }
        finally:
            provider.shutdown()


otlp = OTLPAdapter()
