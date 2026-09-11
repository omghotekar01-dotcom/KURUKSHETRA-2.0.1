"""Illustrative replay-resistant agent-to-agent envelope."""
from sdk.trustkernel.client import TrustKernelClient

client = TrustKernelClient(api_key="tk_live_replace_me")
envelope = client.sign_agent_message(
    sender="coordinator-agent",
    recipient="finance-agent",
    payload={"task": "review invoice 42"},
)
print(envelope)
