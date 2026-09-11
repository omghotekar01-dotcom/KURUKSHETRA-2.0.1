from __future__ import annotations
import os
from typing import Any, Dict, List, Optional

import httpx

from .storage import store


class OTLPAdapter:
    """Dependency-light OTLP/HTTP JSON adapter and transport.

    The JSON builder remains available for offline hackathon demos. When an
    endpoint is configured, send() can deliver the same security spans to a
    collector using OTLP/HTTP JSON semantics.
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
                    {"key": "service.version", "value": {"stringValue": "1.3.0"}},
                ]},
                "scopeSpans": [{"scope": {"name": "trustkernel.security", "version": "1.3.0"}, "spans": spans}],
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
            return {"sent": False, "reason": "otlp_endpoint_not_configured", "spans": 0}
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
            }
        except httpx.HTTPError as exc:
            return {"sent": False, "reason": "otlp_transport_error", "error": str(exc), "spans": span_count, "endpoint": target}


otlp = OTLPAdapter()
