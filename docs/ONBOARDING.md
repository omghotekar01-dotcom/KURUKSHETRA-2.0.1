# Developer Onboarding

## 1. Start TrustKernel

Windows: run `start.bat`.

Manual:

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`.

## 2. Create a workspace

```http
POST /api/workspaces
Content-Type: application/json

{"name":"Acme AI","owner_email":"owner@acme.example"}
```

Store the returned `tk_live_...` key securely. TrustKernel stores its hash, not the raw key.

## 3. Register/choose an agent

An agent identity defines tool grants, operation grants, trusted domains and limits. Workspace-created agents are tenant-scoped.

## 4. Route a tool call through the gateway

```http
POST /api/gateway/evaluate
X-TrustKernel-Key: tk_live_...
Content-Type: application/json

{
  "agent_id":"analytics-agent",
  "intent":{"user_request":"Analyze sales","allowed_tools":["database"],"constraints":{}},
  "action":{"id":"a1","tool":"database","operation":"select","resource":"sales"}
}
```

Only execute the effective action if the result is `ALLOW`, `ALLOW_WITH_LOG`, or a verified `REWRITE`. Do not execute `BLOCK` or `REQUIRE_APPROVAL` results automatically.

## 5. Python SDK pattern

```python
from trustkernel import TrustKernelClient

client = TrustKernelClient(api_key="tk_live_...")
result = client.execute_guarded(
    lambda effective_action: real_tool(effective_action),
    agent_id="analytics-agent",
    user_request="Analyze sales",
    tool="database",
    operation="select",
    resource="sales",
)
```

## 6. Production-oriented controls

Before production set strong values for all signing keys, require API keys, disable legacy actor headers, require governed policy promotion, restrict CORS and use real secret management. See `.env.example` and `docs/PRODUCTION_PROFILE.md` when that profile is added/updated.
