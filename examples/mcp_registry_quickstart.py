"""Illustrative TrustKernel MCP registry flow. Requires the API to be running."""
import hashlib
from sdk.trustkernel.client import TrustKernelClient
from sdk.trustkernel.integrations import MCPGuard

client = TrustKernelClient(api_key="tk_live_replace_me")
manifest = '{"name":"inventory","tools":["lookup"]}'
server = client.register_mcp_server(
    name="Inventory MCP",
    canonical_uri="https://inventory.company.local/mcp",
    manifest=manifest,
    issuer="https://auth.company.local",
    allowed_scopes=["inventory.read"],
)

guard = MCPGuard(
    client,
    agent_id="integration-agent",
    server_id=server["id"],
    canonical_uri=server["canonical_uri"],
    manifest_sha256=hashlib.sha256(manifest.encode()).hexdigest(),
)
print(guard.evaluate_call(user_request="Read current inventory", tool_name="inventory.lookup", scopes=["inventory.read"]))
