# TrustKernel Python SDK

A lightweight, framework-agnostic client and guard layer for routing agent/tool actions through a TrustKernel runtime before execution.

## Install from the repository

```bash
python -m pip install ./sdk
```

## Minimal decision request

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

## Guard the real tool call

Prefer `execute_guarded` when integrating a tool into an agent. The executor is called only when TrustKernel returns an execution-permitting decision (`ALLOW`, `ALLOW_WITH_LOG`, or `REWRITE`). For `BLOCK` and `REQUIRE_APPROVAL`, the executor is not invoked.

```python
from trustkernel import TrustKernelClient

client = TrustKernelClient(base_url="http://127.0.0.1:8000")


def executor(action: dict) -> str:
    return f"would execute {action['tool']}:{action['operation']}"

result = client.execute_guarded(
    executor,
    agent_id="demo-agent",
    user_request="Read a public report",
    tool="files",
    operation="read",
    resource="reports/public.md",
    source_trust="TRUSTED",
    sensitivity="PUBLIC",
)

print(result.decision.decision, result.executed)
```

A runnable example is available at [`../examples/sdk_guard_quickstart.py`](../examples/sdk_guard_quickstart.py).

Framework helpers in `trustkernel.frameworks` and `trustkernel.integrations` keep LangChain/LangGraph/AutoGen/MCP integration thin: TrustKernel remains the enforcement point rather than a framework-specific policy fork.

## Authentication

`TrustKernelClient` supports an API key (`X-TrustKernel-Key`) and/or bearer session token. Production callers should use the identity mechanism configured by the runtime rather than relying on development actor headers.

## Stability

Package version: **1.4.10 alpha**.

This package is alpha software. Bundled, synthetic and imported benchmark results in this repository are regression/evaluation evidence and must not be represented as production security accuracy, certification or universal attack coverage.
