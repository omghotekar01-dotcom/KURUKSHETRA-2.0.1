from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping


_SPIFFE_ID = re.compile(r"^spiffe://([a-z0-9.-]+)(/[^?#]*)?$")
_MAX_ENVELOPE_TTL_SECONDS = 300


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _b64url_decode(value: str) -> bytes:
    if not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("signature must be non-empty base64url without padding")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid base64url signature") from exc


@dataclass(frozen=True)
class WorkloadAttestation:
    """Provider-neutral attestation metadata attached to a workload identity.

    TrustKernel deliberately stores only metadata here. Platform attestation and
    private-key custody remain the responsibility of SPIFFE/SPIRE, a KMS/HSM,
    or another deployment adapter.
    """

    provider: str
    workload_id: str
    issued_at: int
    expires_at: int | None = None
    selectors: Dict[str, str] = field(default_factory=dict)
    evidence_ref: str | None = None

    def validate(self, *, now: int | None = None, max_future_skew: int = 60) -> None:
        current = int(time.time() if now is None else now)
        if not self.provider.strip():
            raise ValueError("attestation provider is required")
        if self.issued_at > current + max_future_skew:
            raise ValueError("attestation issued_at is in the future")
        if self.expires_at is not None and self.expires_at <= current:
            raise ValueError("attestation has expired")
        if self.expires_at is not None and self.expires_at <= self.issued_at:
            raise ValueError("attestation expires_at must be after issued_at")
        if self.provider.lower() in {"spiffe", "spire"} and not _SPIFFE_ID.fullmatch(self.workload_id):
            raise ValueError("SPIFFE workload_id must be a valid spiffe:// URI")
        if not self.workload_id.strip():
            raise ValueError("workload_id is required")
        for key, value in self.selectors.items():
            if not str(key).strip() or not str(value).strip():
                raise ValueError("attestation selectors must have non-empty keys and values")

    def digest(self) -> str:
        payload = {
            "provider": self.provider,
            "workload_id": self.workload_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "selectors": dict(sorted(self.selectors.items())),
            "evidence_ref": self.evidence_ref,
        }
        return hashlib.sha256(canonical_bytes(payload)).hexdigest()

    def public_metadata(self, *, now: int | None = None) -> Dict[str, Any]:
        self.validate(now=now)
        return {
            "provider": self.provider,
            "workload_id": self.workload_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "selectors": dict(self.selectors),
            "evidence_ref": self.evidence_ref,
            "sha256": self.digest(),
        }


class WorkloadSigner(ABC):
    """Adapter boundary for signing without exporting private key material."""

    @property
    @abstractmethod
    def key_reference(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def algorithm(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def sign(self, message: bytes) -> bytes:
        raise NotImplementedError

    def sign_b64url(self, message: bytes) -> str:
        return base64.urlsafe_b64encode(self.sign(message)).decode("ascii").rstrip("=")


class WorkloadVerifier(ABC):
    """Provider-neutral verification boundary paired with WorkloadSigner."""

    @property
    @abstractmethod
    def key_reference(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def algorithm(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def verify(self, message: bytes, signature: bytes) -> bool:
        raise NotImplementedError


class CallbackSigner(WorkloadSigner):
    """Dependency-free adapter for KMS/HSM/SPIFFE client integrations.

    The callback must return raw signature bytes. This keeps cloud/provider SDKs
    optional and prevents TrustKernel from requiring access to private keys.
    """

    def __init__(self, *, key_reference: str, algorithm: str, signer: Callable[[bytes], bytes]):
        if not key_reference.strip():
            raise ValueError("key_reference is required")
        if not algorithm.strip():
            raise ValueError("algorithm is required")
        self._key_reference = key_reference
        self._algorithm = algorithm
        self._signer = signer

    @property
    def key_reference(self) -> str:
        return self._key_reference

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def sign(self, message: bytes) -> bytes:
        signature = self._signer(message)
        if not isinstance(signature, bytes) or not signature:
            raise ValueError("signer callback must return non-empty bytes")
        return signature


class CallbackVerifier(WorkloadVerifier):
    """Dependency-free verification adapter for KMS/HSM/SPIFFE integrations."""

    def __init__(self, *, key_reference: str, algorithm: str, verifier: Callable[[bytes, bytes], bool]):
        if not key_reference.strip():
            raise ValueError("key_reference is required")
        if not algorithm.strip():
            raise ValueError("algorithm is required")
        self._key_reference = key_reference
        self._algorithm = algorithm
        self._verifier = verifier

    @property
    def key_reference(self) -> str:
        return self._key_reference

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def verify(self, message: bytes, signature: bytes) -> bool:
        return bool(self._verifier(message, signature))


def _signature_binding_v2(
    *,
    purpose: str,
    issued_at: int,
    expires_at: int,
    nonce: str,
    message_sha256: str,
    attestation_sha256: str,
    key_reference: str,
    algorithm: str,
) -> bytes:
    return canonical_bytes(
        {
            "version": "trustkernel.workload-signature.v2",
            "purpose": purpose,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "nonce": nonce,
            "message_sha256": message_sha256,
            "attestation_sha256": attestation_sha256,
            "key_reference": key_reference,
            "algorithm": algorithm,
        }
    )


def attested_signature_envelope(
    *,
    signer: WorkloadSigner,
    attestation: WorkloadAttestation,
    message: bytes,
    purpose: str,
    now: int | None = None,
    ttl_seconds: int = 120,
    nonce: str | None = None,
) -> Dict[str, Any]:
    if not purpose.strip():
        raise ValueError("purpose is required")
    if ttl_seconds <= 0 or ttl_seconds > _MAX_ENVELOPE_TTL_SECONDS:
        raise ValueError(f"ttl_seconds must be between 1 and {_MAX_ENVELOPE_TTL_SECONDS}")
    issued_at = int(time.time() if now is None else now)
    expires_at = issued_at + ttl_seconds
    if attestation.expires_at is not None:
        expires_at = min(expires_at, attestation.expires_at)
    if expires_at <= issued_at:
        raise ValueError("attestation lifetime does not permit a signature envelope")
    attestation.validate(now=issued_at)
    envelope_nonce = nonce or secrets.token_urlsafe(18)
    if not envelope_nonce.strip() or len(envelope_nonce) > 256:
        raise ValueError("nonce must be non-empty and at most 256 characters")
    message_sha256 = hashlib.sha256(message).hexdigest()
    attestation_sha256 = attestation.digest()
    binding = _signature_binding_v2(
        purpose=purpose,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=envelope_nonce,
        message_sha256=message_sha256,
        attestation_sha256=attestation_sha256,
        key_reference=signer.key_reference,
        algorithm=signer.algorithm,
    )
    return {
        "version": "trustkernel.workload-signature.v2",
        "purpose": purpose,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": envelope_nonce,
        "message_sha256": message_sha256,
        "attestation": attestation.public_metadata(now=issued_at),
        "key_reference": signer.key_reference,
        "algorithm": signer.algorithm,
        "signature": signer.sign_b64url(binding),
    }


def verify_attested_signature_envelope(
    *,
    verifier: WorkloadVerifier,
    envelope: Mapping[str, Any],
    message: bytes,
    now: int | None = None,
    max_future_skew: int = 60,
    max_ttl_seconds: int = _MAX_ENVELOPE_TTL_SECONDS,
    expected_purpose: str | None = None,
    expected_workload_id: str | None = None,
    nonce_validator: Callable[[str], bool] | None = None,
) -> Dict[str, Any]:
    current = int(time.time() if now is None else now)
    if envelope.get("version") != "trustkernel.workload-signature.v2":
        raise ValueError("unsupported workload signature envelope version")
    purpose = str(envelope.get("purpose") or "")
    nonce = str(envelope.get("nonce") or "")
    key_reference = str(envelope.get("key_reference") or "")
    algorithm = str(envelope.get("algorithm") or "")
    issued_at = int(envelope.get("issued_at"))
    expires_at = int(envelope.get("expires_at"))
    if not purpose or not nonce:
        raise ValueError("purpose and nonce are required")
    if issued_at > current + max_future_skew:
        raise ValueError("signature envelope issued_at is in the future")
    if expires_at <= current:
        raise ValueError("signature envelope has expired")
    if expires_at <= issued_at or expires_at - issued_at > max_ttl_seconds:
        raise ValueError("signature envelope lifetime is invalid")
    if expected_purpose is not None and not hmac.compare_digest(purpose, expected_purpose):
        raise ValueError("signature envelope purpose mismatch")
    if not hmac.compare_digest(key_reference, verifier.key_reference):
        raise ValueError("signature envelope key_reference mismatch")
    if not hmac.compare_digest(algorithm, verifier.algorithm):
        raise ValueError("signature envelope algorithm mismatch")
    if nonce_validator is not None and not nonce_validator(nonce):
        raise ValueError("signature envelope nonce rejected")

    message_sha256 = hashlib.sha256(message).hexdigest()
    if not hmac.compare_digest(str(envelope.get("message_sha256") or ""), message_sha256):
        raise ValueError("signature envelope message digest mismatch")

    raw_attestation = envelope.get("attestation")
    if not isinstance(raw_attestation, Mapping):
        raise ValueError("signature envelope attestation is required")
    attestation = WorkloadAttestation(
        provider=str(raw_attestation.get("provider") or ""),
        workload_id=str(raw_attestation.get("workload_id") or ""),
        issued_at=int(raw_attestation.get("issued_at")),
        expires_at=int(raw_attestation["expires_at"]) if raw_attestation.get("expires_at") is not None else None,
        selectors={str(k): str(v) for k, v in dict(raw_attestation.get("selectors") or {}).items()},
        evidence_ref=str(raw_attestation["evidence_ref"]) if raw_attestation.get("evidence_ref") is not None else None,
    )
    attestation.validate(now=current, max_future_skew=max_future_skew)
    attestation_sha256 = attestation.digest()
    if not hmac.compare_digest(str(raw_attestation.get("sha256") or ""), attestation_sha256):
        raise ValueError("signature envelope attestation digest mismatch")
    if expected_workload_id is not None and not hmac.compare_digest(attestation.workload_id, expected_workload_id):
        raise ValueError("signature envelope workload identity mismatch")

    binding = _signature_binding_v2(
        purpose=purpose,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
        message_sha256=message_sha256,
        attestation_sha256=attestation_sha256,
        key_reference=key_reference,
        algorithm=algorithm,
    )
    signature = _b64url_decode(str(envelope.get("signature") or ""))
    if not verifier.verify(binding, signature):
        raise ValueError("signature envelope verification failed")
    return {
        "verified": True,
        "version": "trustkernel.workload-signature.v2",
        "purpose": purpose,
        "workload_id": attestation.workload_id,
        "key_reference": key_reference,
        "algorithm": algorithm,
        "nonce": nonce,
        "expires_at": expires_at,
    }
