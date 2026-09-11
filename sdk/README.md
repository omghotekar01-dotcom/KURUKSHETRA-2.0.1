# TrustKernel Python SDK

A lightweight client and guard layer for routing agent/tool actions through a TrustKernel runtime before execution.

## Install from the repository

```bash
python -m pip install ./sdk
```

## Minimal use

```python
from trustkernel import TrustKernelClient

client = TrustKernelClient(base_url="http://127.0.0.1:8000")
decision = client.evaluate_action(
    agent_id="demo-agent",
    user_request="Read the public report",
    tool="files",
    operation="read",
    resource="reports/public.md",
)
print(decision.decision, decision.audit_id)
```

Framework helpers in `trustkernel.frameworks` and `trustkernel.integrations` keep LangChain/LangGraph/AutoGen/MCP integration thin: TrustKernel remains the enforcement point rather than a framework-specific policy fork.

This package is alpha software. Benchmark results in this repository are regression/evaluation evidence and must not be represented as production security accuracy or certification.
