import base64
import hashlib
import hmac

import pytest

from app.services.workload_attestation import (
    CallbackSigner,
    CallbackVerifier,
    WorkloadAttestation,
    attested_signature_envelope,
    verify_attested_signature_envelope,
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


def _hmac_adapters(secret: bytes = b"external-test-key"):
    signer = CallbackSigner(
        key_reference="kms://payments/trustkernel-agent-key",
        algorithm="HMAC_SHA256_TEST_ONLY",
        signer=lambda message: hmac.new(secret, message, hashlib.sha256).digest(),
    )
    verifier = CallbackVerifier(
        key_reference="kms://payments/trustkernel-agent-key",
        algorithm="HMAC_SHA256_TEST_ONLY",
        verifier=lambda message, signature: hmac.compare_digest(
            hmac.new(secret, message, hashlib.sha256).digest(), signature
        ),
    )
    return signer, verifier


def _attestation():
    return WorkloadAttestation(
        provider="spiffe",
        workload_id="spiffe://prod.example.com/agents/payment-guard",
        issued_at=100,
        expires_at=500,
        selectors={"k8s:ns": "payments"},
    )


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
    envelope = attested_signature_envelope(
        signer=signer,
        attestation=_attestation(),
        message=b"approve-payment:42",
        purpose="agent-message",
        now=200,
        ttl_seconds=60,
        nonce="nonce-42",
    )

    assert envelope["version"] == "trustkernel.workload-signature.v2"
    assert envelope["expires_at"] == 260
    assert envelope["nonce"] == "nonce-42"
    assert envelope["key_reference"].startswith("kms://")
    assert envelope["attestation"]["workload_id"].startswith("spiffe://")
    assert envelope["signature"] == base64.urlsafe_b64encode(b"remote-signature").decode().rstrip("=")
    assert len(seen) == 1
    assert b"approve-payment:42" not in seen[0]
    assert b"kms://payments/trustkernel-agent-key" in seen[0]
    assert b"ED25519_SHA_512" in seen[0]


def test_v2_envelope_verifies_and_binds_security_metadata():
    signer, verifier = _hmac_adapters()
    envelope = attested_signature_envelope(
        signer=signer,
        attestation=_attestation(),
        message=b"approve-payment:42",
        purpose="agent-message",
        now=200,
        ttl_seconds=60,
        nonce="nonce-42",
    )
    result = verify_attested_signature_envelope(
        verifier=verifier,
        envelope=envelope,
        message=b"approve-payment:42",
        now=220,
        expected_purpose="agent-message",
        expected_workload_id="spiffe://prod.example.com/agents/payment-guard",
        nonce_validator=lambda nonce: nonce == "nonce-42",
    )
    assert result["verified"] is True
    assert result["nonce"] == "nonce-42"

    tampered = dict(envelope)
    tampered["algorithm"] = "RSA_PSS_SHA_256"
    with pytest.raises(ValueError, match="algorithm mismatch"):
        verify_attested_signature_envelope(verifier=verifier, envelope=tampered, message=b"approve-payment:42", now=220)

    tampered = dict(envelope)
    tampered["key_reference"] = "kms://attacker/key"
    with pytest.raises(ValueError, match="key_reference mismatch"):
        verify_attested_signature_envelope(verifier=verifier, envelope=tampered, message=b"approve-payment:42", now=220)


def test_v2_envelope_expiry_message_digest_and_nonce_fail_closed():
    signer, verifier = _hmac_adapters()
    envelope = attested_signature_envelope(
        signer=signer,
        attestation=_attestation(),
        message=b"approve-payment:42",
        purpose="agent-message",
        now=200,
        ttl_seconds=30,
        nonce="nonce-once",
    )
    with pytest.raises(ValueError, match="expired"):
        verify_attested_signature_envelope(verifier=verifier, envelope=envelope, message=b"approve-payment:42", now=231)
    with pytest.raises(ValueError, match="message digest mismatch"):
        verify_attested_signature_envelope(verifier=verifier, envelope=envelope, message=b"approve-payment:43", now=220)
    with pytest.raises(ValueError, match="nonce rejected"):
        verify_attested_signature_envelope(
            verifier=verifier,
            envelope=envelope,
            message=b"approve-payment:42",
            now=220,
            nonce_validator=lambda _nonce: False,
        )


def test_v2_envelope_ttl_is_bounded():
    signer, _ = _hmac_adapters()
    with pytest.raises(ValueError, match="ttl_seconds"):
        attested_signature_envelope(
            signer=signer,
            attestation=_attestation(),
            message=b"x",
            purpose="agent-message",
            now=200,
            ttl_seconds=301,
        )
