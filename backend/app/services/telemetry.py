from __future__ import annotations
import time
from typing import Any, Dict, List, Optional
from .storage import store


class TelemetryService:
    def emit(self, event_name: str, *, workspace_id: Optional[str], agent_id: Optional[str], attributes: Dict[str, Any]) -> None:
        store.append_telemetry(time.time(), event_name, workspace_id, agent_id, attributes)

    def export(self, workspace_id: Optional[str] = None, limit: int = 500) -> Dict[str, Any]:
        events = store.telemetry(workspace_id, max(1, min(limit, 2000)))
        return {
            "schema": "trustkernel.telemetry.v1",
            "semantic_alignment": "OpenTelemetry-style GenAI/tool-call attributes; exporter is dependency-free JSON in MVP",
            "events": events,
        }


telemetry = TelemetryService()
