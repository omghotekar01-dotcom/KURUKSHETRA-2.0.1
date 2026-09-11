import base64

import pytest

from app.services.workload_attestation import (
    CallbackSigner,
    WorkloadAttestation,
    attested_signature_envelope,
)


def test_spiffe_attestation_metadata_and_digest_are_stable():
    item = WorkloadAttestation(
        provider="spiffe",
        workload_id="spiffe://prod.example.com/agents/payment-guard",
        issued_at=100,
        expires_at=500,
        selectors={"k8s:ns": "payments", "k8s:sa": "guard"},
        evidence_ref="workload-api:x509-svid",
    )
    item.validate(now=200)
    first = item.public_metadata(now=200)
    second = item.public_metadata(now=200)
    assert first["sha256"] == second["sha256"]
    assert len(first["sha256"]) == 64


def test_invalid_spiffe_id_and_expired_attestation_fail_closed():
    with pytest.raises(ValueError, match="spiffe://"):
        WorkloadAttestation(provider="spiffe", workload_id="https://example.com/agent", issued_at=100).validate(now=200)

    with pytest.raises(ValueError, match="expired"):
        WorkloadAttestation(
            provider="spire",
            workload_id="spiffe://prod.example.com/agent",
            issued_at=100,
            expires_at=150,
        ).validate(now=200)


def test_callback_signer_keeps_key_external_and_binds_attestation():
    seen = []

    def external_sign(message: bytes) -> bytes:
        seen.append(message)
        return b"remote-signature"

    signer = CallbackSigner(
        key_reference="kms://payments/trustkernel-agent-key",
        algorithm="ED25519_SHA_512",
        signer=external_sign,
    )
    attestation = WorkloadAttestation(
        provider="spiffe",
        workload_id="spiffe://prod.example.com/agents/payment-guard",
        issued_at=100,
        expires_at=500,
        selectors={"k8s:ns": "payments"},
    )
    envelope = attested_signature_envelope(
        signer=signer,
        attestation=attestation,
        message=b"approve-payment:42",
        purpose="agent-message",
        now=200,
    )

    assert envelope["key_reference"].startswith("kms://")
    assert envelope["attestation"]["workload_id"].startswith("spiffe://")
    assert envelope["signature"] == base64.urlsafe_b64encode(b"remote-signature").decode().rstrip("=")
    assert len(seen) == 1
    assert b"approve-payment:42" not in seen[0]
