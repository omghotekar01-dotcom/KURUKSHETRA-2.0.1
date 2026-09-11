"""TrustKernel v1.2 signed-member-session + governed-policy flow."""
from sdk.trustkernel import TrustKernelClient

WORKSPACE_ID = "replace-with-workspace-id"
API_KEY = "replace-with-api-key"
OWNER_EMAIL = "owner@example.com"
BUNDLE_ID = "replace-with-published-policy-bundle-id"

client = TrustKernelClient(api_key=API_KEY)
session = client.create_member_session(WORKSPACE_ID, OWNER_EMAIL)
print("Signed in as", session["principal"]["sub"])

change = client.propose_policy_change(WORKSPACE_ID, "enterprise-default", BUNDLE_ID)
print("Change request", change["id"], "diff entries", len(change["diff"]))

result = client.vote_policy_change(WORKSPACE_ID, change["id"], "APPROVE")
print("Policy change status", result["status"])
