from app.services.otlp import otlp
from app.services.telemetry import telemetry


class _Response:
    status_code = 200


def test_otlp_http_transport(monkeypatch):
    telemetry.emit(
        "trustkernel.test.event",
        workspace_id="ws_otlp_test",
        agent_id="agent_otlp_test",
        attributes={"trustkernel.decision": "ALLOW", "trustkernel.risk_score": 12},
    )

    captured = {}

    def fake_post(url, json, headers, timeout, follow_redirects):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        captured["timeout"] = timeout
        captured["follow_redirects"] = follow_redirects
        return _Response()

    monkeypatch.setattr("app.services.otlp.httpx.post", fake_post)
    result = otlp.send("ws_otlp_test", endpoint="http://collector.test/v1/traces")

    assert result["sent"] is True
    assert result["status_code"] == 200
    assert result["spans"] >= 1
    assert captured["url"] == "http://collector.test/v1/traces"
    assert captured["headers"]["Content-Type"] == "application/json"
    resource_spans = captured["json"]["resourceSpans"]
    assert resource_spans
