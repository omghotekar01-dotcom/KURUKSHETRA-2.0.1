from __future__ import annotations

import hashlib
import hmac
import os
import uuid

import pytest

from app.services.replay import InMemoryReplayGuard, RedisReplayGuard
from app.services.workload_attestation import (
    CallbackSigner,
    CallbackVerifier,
    WorkloadAttestation,
    attested_signature_envelope,
    verify_attested_signature_envelope,
)


def _adapters(secret: bytes = b"replay-test-key"):
    signer = CallbackSigner(
        key_reference="kms://prod/agent-key",
        algorithm="HMAC_SHA256_TEST_ONLY",
        signer=lambda message: hmac.new(secret, message, hashlib.sha256).digest(),
    )
    verifier = CallbackVerifier(
        key_reference="kms://prod/agent-key",
        algorithm="HMAC_SHA256_TEST_ONLY",
        verifier=lambda message, signature: hmac.compare_digest(
            hmac.new(secret, message, hashlib.sha256).digest(), signature
        ),
    )
    return signer, verifier


def _envelope(nonce: str = "nonce-once"):
    signer, verifier = _adapters()
    attestation = WorkloadAttestation(
        provider="spiffe",
        workload_id="spiffe://prod.example.com/agents/guard",
        issued_at=100,
        expires_at=500,
    )
    envelope = attested_signature_envelope(
        signer=signer,
        attestation=attestation,
        message=b"approve:42",
        purpose="agent-message",
        now=200,
        ttl_seconds=60,
        nonce=nonce,
    )
    return verifier, envelope


def test_invalid_signature_cannot_burn_legitimate_nonce():
    verifier, envelope = _envelope()
    guard = InMemoryReplayGuard(ttl_seconds=300)
    calls: list[str] = []

    def consume(nonce: str) -> bool:
        calls.append(nonce)
        return guard.consume(nonce)

    forged = dict(envelope)
    forged["signature"] = "Zm9yZ2Vk"
    with pytest.raises(ValueError, match="verification failed"):
        verify_attested_signature_envelope(
            verifier=verifier,
            envelope=forged,
            message=b"approve:42",
            now=220,
            nonce_validator=consume,
        )

    assert calls == []
    result = verify_attested_signature_envelope(
        verifier=verifier,
        envelope=envelope,
        message=b"approve:42",
        now=220,
        nonce_validator=consume,
    )
    assert result["verified"] is True
    assert calls == ["nonce-once"]


def test_in_memory_replay_guard_enforces_single_use_and_hashes_storage_keys():
    guard = InMemoryReplayGuard(ttl_seconds=300)
    assert guard.consume("nonce-a") is True
    assert guard.consume("nonce-a") is False
    assert guard.consume("nonce-b") is True
    assert "nonce-a" not in guard._seen


def test_redis_replay_guard_is_shared_and_atomic_when_live_redis_is_available():
    redis_url = os.getenv("TRUSTKERNEL_REDIS_TEST_URL")
    if not redis_url:
        pytest.skip("TRUSTKERNEL_REDIS_TEST_URL is not configured")

    prefix = f"trustkernel:test-replay:{uuid.uuid4()}"
    first = RedisReplayGuard(redis_url, key_prefix=prefix)
    second = RedisReplayGuard(redis_url, key_prefix=prefix)
    nonce = f"nonce-{uuid.uuid4()}"

    assert first.ping()
    assert first.consume(nonce) is True
    assert second.consume(nonce) is False
    key = first._key(nonce)
    assert nonce not in key
    assert len(key.rsplit(":", 1)[-1]) == 64
