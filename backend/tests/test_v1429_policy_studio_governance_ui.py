from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_policy_studio_loads_governance_assets():
    index = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    assert '/static/governance.css' in index
    assert '/static/governance.js' in index


def test_governance_console_uses_workspace_scoped_policy_change_api():
    script = (ROOT / "frontend" / "governance.js").read_text(encoding="utf-8")
    assert '/api/workspaces/${encodeURIComponent(workspaceId)}/policy-changes' in script
    assert '/vote/${decision}' in script
    assert "'X-TrustKernel-Key': state.apiKey" in script
    assert 'Authorization = `Bearer ${state.bearer}`' in script
    assert "out['X-TrustKernel-Actor'] = state.actor" in script


def test_governance_console_keeps_credentials_memory_only():
    script = (ROOT / "frontend" / "governance.js").read_text(encoding="utf-8")
    assert 'localStorage' not in script
    assert 'sessionStorage' not in script
    assert 'document.cookie' not in script
    assert 'type="password"' in script
    assert 'autocomplete="off"' in script
    assert 'Use a signed member session in production' in script


def test_governance_console_surfaces_four_eyes_and_activation_state():
    script = (ROOT / "frontend" / "governance.js").read_text(encoding="utf-8")
    for token in ('required_approvals', 'approval_count', 'four_eyes', 'ACTIVATED', 'REJECTED', 'PENDING'):
        assert token in script
    assert "set('govFourEyes', 'active')" in script
    assert "set('govActivate', 'done')" in script
