from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_and_readiness_surface():
    health = client.get('/health')
    assert health.status_code == 200
    assert health.json()['service'] == 'TrustKernel'
    ready = client.get('/ready')
    assert ready.status_code == 200
    assert 'checks' in ready.json()


def test_judge_mode_has_five_contrasting_scenarios():
    response = client.post('/api/judge-demo/run')
    assert response.status_code == 200
    sequence = response.json()['sequence']
    assert len(sequence) == 5
    decisions = {item['decision'] for item in sequence}
    assert 'BLOCK' in decisions
    assert 'REWRITE' in decisions
    assert 'REQUIRE_APPROVAL' in decisions
    assert decisions & {'ALLOW', 'ALLOW_WITH_LOG'}


def test_workspace_key_auth_and_gateway():
    created = client.post('/api/workspaces', json={'name':'Smoke Workspace','owner_email':'owner@example.com'}).json()
    headers = {'X-TrustKernel-Key': created['api_key']}
    agents = client.get('/api/agents', headers=headers)
    assert agents.status_code == 200
    payload = {
        'agent_id':'analytics-agent',
        'intent':{'user_request':'Read sales data','allowed_tools':['database'],'constraints':{}},
        'action':{'id':'smoke-1','tool':'database','operation':'select','resource':'sales'}
    }
    result = client.post('/api/gateway/evaluate', headers=headers, json=payload)
    assert result.status_code == 200
    assert result.json()['decision'] in {'ALLOW','ALLOW_WITH_LOG'}
