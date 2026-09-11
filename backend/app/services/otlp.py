from __future__ import annotations
from typing import Any, Dict, List, Optional
from .storage import store


class OTLPAdapter:
    """Builds an OTLP/HTTP JSON-shaped trace export without external SDK deps."""

    def export_json(self, workspace_id: Optional[str] = None, limit: int = 500) -> Dict[str, Any]:
        events = store.telemetry(workspace_id, max(1, min(limit, 2000)))
        spans: List[Dict[str, Any]] = []
        for index, event in enumerate(events):
            attrs = []
            for key, value in event.get("attributes", {}).items():
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
                "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "trustkernel"}}]},
                "scopeSpans": [{"scope": {"name": "trustkernel.security", "version": "1.1.0"}, "spans": spans}],
            }],
            "note": "OTLP/HTTP JSON-shaped MVP adapter; production transport should use the official OpenTelemetry SDK/exporter.",
        }


otlp = OTLPAdapter()
