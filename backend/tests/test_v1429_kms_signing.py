import pytest

from app.services.kms_signing import AwsKmsSigner, AwsKmsVerifier
from app.services.workload_attestation import WorkloadAttestation, attested_signature_envelope, verify_attested_signature_envelope


class FakeKmsClient:
    def __init__(self):
        self.sign_calls = []
        self.verify_calls = []

    def sign(self, **kwargs):
        self.sign_calls.append(kwargs)
        return {"Signature": b"kms-signature"}

    def verify(self, **kwargs):
        self.verify_calls.append(kwargs)
        return {"SignatureValid": kwargs.get("Signature") == b"kms-signature"}


def _attestation():
    return WorkloadAttestation(
        provider="spiffe",
        workload_id="spiffe://prod.example.com/agents/payment-guard",
        issued_at=100,
        expires_at=500,
        selectors={"k8s:ns": "payments"},
        evidence_ref="workload-api:x509-svid",
    )


def test_aws_kms_adapter_keeps_key_external_and_uses_explicit_raw_semantics():
    client = FakeKmsClient()
    signer = AwsKmsSigner(
        client=client,
        key_id="arn:aws:kms:ap-south-1:111122223333:key/example",
        signing_algorithm="ECDSA_SHA_256",
    )
    verifier = AwsKmsVerifier(
        client=client,
        key_id="arn:aws:kms:ap-south-1:111122223333:key/example",
        signing_algorithm="ECDSA_SHA_256",
    )

    envelope = attested_signature_envelope(
        signer=signer,
        attestation=_attestation(),
        message=b"approve-payment:42",
        purpose="agent-message",
        now=200,
        ttl_seconds=60,
        nonce="kms-nonce-42",
    )
    result = verify_attested_signature_envelope(
        verifier=verifier,
        envelope=envelope,
        message=b"approve-payment:42",
        now=220,
        expected_purpose="agent-message",
        expected_workload_id="spiffe://prod.example.com/agents/payment-guard",
    )

    assert result["verified"] is True
    assert envelope["key_reference"].startswith("aws-kms:")
    assert client.sign_calls[0]["MessageType"] == "RAW"
    assert client.verify_calls[0]["MessageType"] == "RAW"
    assert client.sign_calls[0]["SigningAlgorithm"] == "ECDSA_SHA_256"
    assert "PrivateKey" not in client.sign_calls[0]


def test_aws_kms_adapter_rejects_unknown_algorithms():
    with pytest.raises(ValueError, match="unsupported AWS KMS signing algorithm"):
        AwsKmsSigner(client=FakeKmsClient(), key_id="alias/trustkernel", signing_algorithm="AES_GCM")


def test_aws_kms_adapter_fails_closed_above_raw_message_limit():
    signer = AwsKmsSigner(
        client=FakeKmsClient(),
        key_id="alias/trustkernel",
        signing_algorithm="ECDSA_SHA_256",
    )
    with pytest.raises(ValueError, match="4096"):
        signer.sign(b"x" * 4097)


def test_aws_kms_verifier_returns_false_for_invalid_signature():
    verifier = AwsKmsVerifier(
        client=FakeKmsClient(),
        key_id="alias/trustkernel",
        signing_algorithm="ECDSA_SHA_256",
    )
    assert verifier.verify(b"binding", b"different-signature") is False
