# TrustKernel — Product / Startup Direction

## Category
Agent Runtime Security / AI Control Plane

## Product thesis
Enterprises are increasingly allowing AI agents to touch high-impact systems. TrustKernel provides an execution boundary independent of the model vendor.

## Developer experience

```python
from trustkernel import TrustKernelClient

kernel = TrustKernelClient(api_key="tk_live_...")
result = kernel.execute_guarded(real_tool, agent_id="coding-agent", user_request="Prepare change for review", tool="github", operation="push", resource="main")
```

## Enterprise policy examples
- Never transmit secrets to untrusted domains.
- Production database writes require explicit intent and scoped authorization.
- Payments above a configured threshold require human approval.
- Source-control pushes to protected branches require review or repair.
- PII may only flow to approved processors.
- IAM privilege expansion is blocked unless explicitly approved.

## Commercial path
1. Open-source local runtime / SDK.
2. Team dashboard and policy packs.
3. Enterprise connectors and centralized policy management.
4. Compliance evidence, audit exports, fleet-wide agent observability and managed control plane.

## Defensible moat
The moat is not an LLM wrapper. It is the normalized action schema, policy language, identity/action/data-flow graph, simulation/repair adapters, organization-specific security telemetry, evaluation corpus and integrations around the execution boundary.
