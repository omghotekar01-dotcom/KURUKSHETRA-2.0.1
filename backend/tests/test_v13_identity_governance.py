import json
import os
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from app.services.approval_groups import approval_groups
from app.services.members import members
from app.services.oidc import OIDCVerifier
from app.services.policies import load_policy, publish_policy_document
from app.services.policy_changes import policy_changes
from app.services.workspaces import workspaces


def test_oidc_static_jwks_verification(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk["kid"] = "test-key-1"

    monkeypatch.setenv("TRUSTKERNEL_OIDC_ISSUER", "https://idp.example.test")
    monkeypatch.setenv("TRUSTKERNEL_OIDC_AUDIENCE", "trustkernel")
    monkeypatch.setenv("TRUSTKERNEL_OIDC_JWKS_JSON", json.dumps({"keys": [public_jwk]}))
    monkeypatch.setenv("TRUSTKERNEL_OIDC_ALGORITHMS", "RS256")

    now = int(time.time())
    token = jwt.encode(
        {
            "sub": "user-123",
            "email": "analyst@example.test",
            "workspace_id": "ws_test",
            "iss": "https://idp.example.test",
            "aud": "trustkernel",
            "iat": now,
            "exp": now + 300,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key-1"},
    )

    claims, reason = OIDCVerifier().verify(token)
    assert reason == "verified"
    assert claims is not None
    assert claims["sub"] == "analyst@example.test"
    assert claims["workspace_id"] == "ws_test"
    assert claims["auth_source"] == "oidc"


def test_policy_change_requires_distinct_approver(monkeypatch):
    monkeypatch.setenv("TRUSTKERNEL_POLICY_FOUR_EYES", "1")
    workspace = workspaces.create("four-eyes-test", owner_email="owner@example.test")
    workspace_id = workspace["id"]
    requester = "owner@example.test"
    approver = "security@example.test"

    members.upsert(workspace_id, approver, "security_analyst")
    approval_groups.upsert(
        workspace_id,
        "security-approvers",
        roles=["owner", "admin", "security_analyst", "approver"],
        members_list=[requester, approver],
        min_approvals=1,
    )

    policy = json.loads(json.dumps(load_policy("enterprise-default")))
    policy["version"] = int(policy["version"]) + 1000
    policy["payments"]["default_auto_limit"] = 12345
    bundle = publish_policy_document("enterprise-default", policy, created_by=requester, source="test")
    request = policy_changes.propose(workspace_id, "enterprise-default", bundle["id"], requester)

    try:
        policy_changes.vote(request["id"], requester, "APPROVE")
        assert False, "requester self-approval should be rejected"
    except PermissionError as exc:
        assert "self-approval" in str(exc).lower()

    approved = policy_changes.vote(request["id"], approver, "APPROVE")
    assert approved["status"] == "ACTIVATED"
    assert approved["approval_count"] >= 1
