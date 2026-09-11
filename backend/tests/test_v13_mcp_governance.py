from app.services.approval_groups import approval_groups
from app.services.mcp_governance import mcp_governance
from app.services.members import members
from app.services.mcp_registry import mcp_registry
from app.services.workspaces import workspaces


def test_mcp_registry_change_requires_distinct_approver():
    workspace = workspaces.create("mcp-governance-test", owner_email="owner-mcp@example.test")
    workspace_id = workspace["id"]
    requester = "owner-mcp@example.test"
    approver = "security-mcp@example.test"

    members.upsert(workspace_id, approver, "security_analyst")
    approval_groups.upsert(
        workspace_id,
        "security-approvers",
        roles=["owner", "admin", "security_analyst", "approver"],
        members_list=[requester, approver],
        min_approvals=1,
    )

    request = mcp_governance.propose(
        workspace_id,
        requested_by=requester,
        name="Trusted Calculator",
        canonical_uri="https://mcp.example.test/calculator",
        manifest="calculator-v1",
        issuer="https://idp.example.test",
        allowed_scopes=["calculate.read"],
    )
    assert request["signature_valid"] is True
    assert request["payload_hash_valid"] is True

    try:
        mcp_governance.vote(request["id"], requester, "APPROVE")
        assert False, "requester self-approval should be rejected"
    except PermissionError as exc:
        assert "self-approval" in str(exc).lower()

    applied = mcp_governance.vote(request["id"], approver, "APPROVE")
    assert applied["status"] == "APPLIED"
    server = mcp_registry.get(workspace_id, canonical_uri="https://mcp.example.test/calculator")
    assert server is not None
    assert server["status"] == "ACTIVE"
    assert server["allowed_scopes"] == ["calculate.read"]
