from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping


_SPIFFE_ID = re.compile(r"^spiffe://([a-z0-9.-]+)(/[^?#]*)?$")


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


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


class CallbackSigner(WorkloadSigner):
    """Small dependency-free adapter for KMS/HSM/SPIFFE client integrations.

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


def attested_signature_envelope(
    *,
    signer: WorkloadSigner,
    attestation: WorkloadAttestation,
    message: bytes,
    purpose: str,
    now: int | None = None,
) -> Dict[str, Any]:
    if not purpose.strip():
        raise ValueError("purpose is required")
    issued_at = int(time.time() if now is None else now)
    attestation.validate(now=issued_at)
    message_sha256 = hashlib.sha256(message).hexdigest()
    binding = canonical_bytes(
        {
            "purpose": purpose,
            "issued_at": issued_at,
            "message_sha256": message_sha256,
            "attestation_sha256": attestation.digest(),
        }
    )
    return {
        "version": "trustkernel.workload-signature.v1",
        "purpose": purpose,
        "issued_at": issued_at,
        "message_sha256": message_sha256,
        "attestation": attestation.public_metadata(now=issued_at),
        "key_reference": signer.key_reference,
        "algorithm": signer.algorithm,
        "signature": signer.sign_b64url(binding),
    }
