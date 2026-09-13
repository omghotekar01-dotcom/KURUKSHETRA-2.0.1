from app.services.incidents import IncidentService


def _incident():
    return {
        "id": "INC-DEMO",
        "audit_id": "AUD-DEMO",
        "workspace_id": "ws-1",
        "severity": "CRITICAL",
        "status": "OPEN",
        "created_at": 1234.5,
        "payload": {
            "decision": "BLOCK",
            "risk_score": 96,
            "agent_id": "agent-finance",
            "policy": {"name": "prod"},
            "findings": [
                {
                    "code": "TK-MCP-TOKEN-PASSTHROUGH-001",
                    "title": "Client token passthrough detected",
                    "severity": "CRITICAL",
                }
            ],
            "graph_snapshot": {"patterns": [{"name": "agent -> untrusted MCP -> downstream API"}]},
            "action_results": [{"action": "deny", "status": "completed"}],
            "recommended_remediation": ["Use a separate downstream token."],
        },
    }


def test_investigation_exposes_recorded_causal_chain(monkeypatch):
    service = IncidentService()
    monkeypatch.setattr(service, "get", lambda incident_id: _incident())

    result = service.investigation("INC-DEMO")

    assert result is not None
    stages = [entry["stage"] for entry in result["causal_chain"]]
    assert stages == ["workload", "finding", "attack_path", "decision"]
    assert result["causal_chain"][1]["code"] == "TK-MCP-TOKEN-PASSTHROUGH-001"
    assert result["causal_chain"][-1]["risk_score"] == 96


def test_remediation_timeline_separates_recorded_from_recommended(monkeypatch):
    service = IncidentService()
    monkeypatch.setattr(service, "get", lambda incident_id: _incident())

    result = service.investigation("INC-DEMO")

    timeline = result["remediation_timeline"]
    assert [entry["sequence"] for entry in timeline] == list(range(1, len(timeline) + 1))
    assert timeline[0]["state"] == "recorded"
    assert timeline[1]["label"] == "Execution blocked"
    assert any(entry["phase"] == "remediate" and entry["state"] == "recommended" for entry in timeline)
    assert timeline[-1]["phase"] == "verify"
    assert timeline[-1]["state"] == "recommended"


def test_causal_chain_does_not_invent_graph_patterns(monkeypatch):
    item = _incident()
    item["payload"]["graph_snapshot"] = {}
    service = IncidentService()
    monkeypatch.setattr(service, "get", lambda incident_id: item)

    result = service.investigation("INC-DEMO")

    assert not any(entry["stage"] == "attack_path" for entry in result["causal_chain"])
