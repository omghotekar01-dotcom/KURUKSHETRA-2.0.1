"""Minimal TrustKernel SDK guard example.

Run the TrustKernel backend first, install the SDK with `python -m pip install ./sdk`,
then execute this file from the repository root.
"""

from trustkernel import TrustKernelClient


client = TrustKernelClient(base_url="http://127.0.0.1:8000")


def read_file(action: dict) -> str:
    """Example executor. Replace with the real tool call in your agent application."""
    resource = action.get("resource", "")
    return f"tool would read: {resource}"


result = client.execute_guarded(
    read_file,
    agent_id="demo-agent",
    user_request="Read the public quarterly report",
    tool="files",
    operation="read",
    resource="reports/public-quarterly.md",
    source_trust="TRUSTED",
    sensitivity="PUBLIC",
)

print("decision:", result.decision.decision)
print("risk_score:", result.decision.risk_score)
print("audit_id:", result.decision.audit_id)
print("executed:", result.executed)
print("value:", result.value)

# `execute_guarded` calls the executor only when the runtime decision permits it.
# For BLOCK / REQUIRE_APPROVAL outcomes, the example executor is not invoked.
