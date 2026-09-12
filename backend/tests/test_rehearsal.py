from __future__ import annotations

import rehearsal


def test_rehearsal_aggregates_green_gates(monkeypatch):
    monkeypatch.setattr(rehearsal, "run_diagnostics", lambda: {"passed": True})
    monkeypatch.setattr(rehearsal, "run_release_check", lambda: {"passed": True, "version": "1.4.11"})
    monkeypatch.setattr(rehearsal, "_run_tests", lambda: {"passed": True, "summary": "ok"})
    monkeypatch.setattr(rehearsal, "_benchmark_gate", lambda iterations: {"passed": True, "scenario_count": 19})
    monkeypatch.setattr(rehearsal, "run_judge_check", lambda: {"passed": True})

    result = rehearsal.run(iterations=1)

    assert result["schema"] == "trustkernel.rehearsal.v2"
    assert result["passed"] is True
    assert result["status"] == "ready"
    assert result["gates"]["release_integrity"] is True
    assert all(result["gates"].values())
    assert "not production security accuracy" in result["evidence_note"]


def test_rehearsal_fails_closed_when_any_gate_fails(monkeypatch):
    monkeypatch.setattr(rehearsal, "run_diagnostics", lambda: {"passed": True})
    monkeypatch.setattr(rehearsal, "run_release_check", lambda: {"passed": True, "version": "1.4.11"})
    monkeypatch.setattr(rehearsal, "_run_tests", lambda: {"passed": False, "summary": "failed"})
    monkeypatch.setattr(rehearsal, "_benchmark_gate", lambda iterations: {"passed": True})
    monkeypatch.setattr(rehearsal, "run_judge_check", lambda: {"passed": True})

    result = rehearsal.run(iterations=1)

    assert result["passed"] is False
    assert result["status"] == "failed"
    assert result["gates"]["tests"] is False


def test_rehearsal_fails_closed_when_release_integrity_fails(monkeypatch):
    monkeypatch.setattr(rehearsal, "run_diagnostics", lambda: {"passed": True})
    monkeypatch.setattr(rehearsal, "run_release_check", lambda: {"passed": False, "version": "1.4.11"})
    monkeypatch.setattr(rehearsal, "_run_tests", lambda: {"passed": True, "summary": "ok"})
    monkeypatch.setattr(rehearsal, "_benchmark_gate", lambda iterations: {"passed": True})
    monkeypatch.setattr(rehearsal, "run_judge_check", lambda: {"passed": True})

    result = rehearsal.run(iterations=1)

    assert result["passed"] is False
    assert result["status"] == "failed"
    assert result["gates"]["release_integrity"] is False


def test_benchmark_gate_accepts_bundled_regression_suite():
    result = rehearsal._benchmark_gate(iterations=1)

    assert result["passed"] is True
    assert result["scenario_count"] > 0
    assert result["overall_expected_outcome_rate"] == 1.0
    assert result["owasp_agentic_top10_coverage"] is True
