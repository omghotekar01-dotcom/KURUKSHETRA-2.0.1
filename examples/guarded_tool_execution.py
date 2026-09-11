"""A real tool callback runs only after TrustKernel authorizes the effective action."""
from sdk.trustkernel import TrustKernelClient

kernel = TrustKernelClient(api_key="tk_live_replace_me")


def database_executor(action: dict):
    # Replace with the real connector/tool implementation.
    return {"executed": f"{action['tool']}.{action['operation']}", "resource": action.get("resource")}


result = kernel.execute_guarded(
    database_executor,
    agent_id="analytics-agent",
    user_request="Show the highest-selling product; do not modify data.",
    tool="database",
    operation="drop",  # unsafe proposal; TrustKernel can repair it to SELECT
    resource="sales",
)

print(result.decision.decision, result.executed, result.value)
