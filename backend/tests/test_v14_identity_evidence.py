import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from app.bootstrap import app
from app.services.governance_evidence import governance_evidence
from app.services.oidc import OIDCVerifier
from app.services.policies import load_policy, publish_policy_document
from app.services.policy_changes import policy_changes
from app.services.workspaces import workspaces


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def test_oidc_discovery_exact_issuer_and_role_mapping(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk.update({"kid": "rotating-key-1", "alg": "RS256", "use": "sig"})

    issuer = "https://idp.example.test"
    monkeypatch.setenv("TRUSTKERNEL_OIDC_ISSUER", issuer)
    monkeypatch.setenv("TRUSTKERNEL_OIDC_AUDIENCE", "trustkernel-api")
    monkeypatch.delenv("TRUSTKERNEL_OIDC_JWKS_URL", raising=False)
    monkeypatch.delenv("TRUSTKERNEL_OIDC_JWKS_JSON", raising=False)
    monkeypatch.setenv("TRUSTKERNEL_OIDC_ROLE_CLAIM", "groups")
    monkeypatch.setenv("TRUSTKERNEL_OIDC_ROLE_MAP_JSON", json.dumps({"tk-security": "security_analyst"}))

    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        if url.endswith("/.well-known/openid-configuration"):
            return FakeResponse({
                "issuer": issuer,
                "jwks_uri": "https://idp.example.test/keys",
                "authorization_endpoint": "https://idp.example.test/authorize",
                "token_endpoint": "https://idp.example.test/token",
                "id_token_signing_alg_values_supported": ["RS256"],
            })
        return FakeResponse({"keys": [public_jwk]})

    monkeypatch.setattr("app.services.oidc.httpx.get", fake_get)
    verifier = OIDCVerifier()
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": "user-1",
            "email": "security@example.test",
            "workspace_id": "ws_enterprise",
            "groups": ["employees", "tk-security"],
            "iss": issuer,
            "aud": "trustkernel-api",
            "iat": now,
            "exp": now + 300,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "rotating-key-1"},
    )

    claims, reason = verifier.verify(token)
    assert reason == "verified"
    assert claims["mapped_role"] == "security_analyst"
    assert claims["external_roles"] == ["employees", "tk-security"]
    assert calls[0].endswith("/.well-known/openid-configuration")
    assert calls[1] == "https://idp.example.test/keys"


def test_oidc_discovery_rejects_issuer_mismatch(monkeypatch):
    monkeypatch.setenv("TRUSTKERNEL_OIDC_ISSUER", "https://idp.example.test")
    monkeypatch.setenv("TRUSTKERNEL_OIDC_AUDIENCE", "trustkernel-api")
    monkeypatch.delenv("TRUSTKERNEL_OIDC_JWKS_URL", raising=False)
    monkeypatch.delenv("TRUSTKERNEL_OIDC_JWKS_JSON", raising=False)
    monkeypatch.setattr(
        "app.services.oidc.httpx.get",
        lambda *args, **kwargs: FakeResponse({"issuer": "https://evil.example.test", "jwks_uri": "https://evil.example.test/keys"}),
    )
    with pytest.raises(ValueError, match="issuer does not match"):
        OIDCVerifier().metadata()


def test_governance_evidence_detects_tampering():
    workspace = workspaces.create("evidence-test", owner_email="owner-evidence@example.test")
    policy = json.loads(json.dumps(load_policy("enterprise-default")))
    policy["version"] = int(policy["version"]) + 2000
    policy["payments"]["default_auto_limit"] = 4242
    bundle = publish_policy_document("enterprise-default", policy, created_by="owner-evidence@example.test", source="test-v14")
    change = policy_changes.propose(workspace["id"], "enterprise-default", bundle["id"], "owner-evidence@example.test")

    envelope = governance_evidence.policy_change(change["id"])
    assert governance_evidence.verify(envelope)["valid"] is True

    tampered = json.loads(json.dumps(envelope))
    tampered["record"]["status"] = "ACTIVATED"
    result = governance_evidence.verify(tampered)
    assert result["valid"] is False
    assert result["hash_valid"] is False


def test_v14_capabilities_surface():
    client = TestClient(app)
    response = client.get("/api/v14/capabilities")
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == "1.4.0"
    assert body["identity"]["oidc_discovery"] is True
    assert body["governance"]["portable_signed_evidence"] is True
