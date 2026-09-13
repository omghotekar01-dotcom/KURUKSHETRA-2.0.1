from __future__ import annotations

from typing import Any

from app.services.workload_attestation import WorkloadSigner, WorkloadVerifier


# AWS KMS accepts RAW messages up to 4096 bytes for Sign/Verify. TrustKernel
# deliberately fails closed above that limit instead of silently switching to
# DIGEST semantics, which would require algorithm-specific pre-hashing rules.
_MAX_RAW_MESSAGE_BYTES = 4096

# Algorithms supported by asymmetric SIGN_VERIFY KMS keys. Keeping an explicit
# allow-list prevents a caller typo or an encryption-only algorithm name from
# becoming envelope metadata that can never be verified.
AWS_KMS_SIGNING_ALGORITHMS = frozenset(
    {
        "RSASSA_PSS_SHA_256",
        "RSASSA_PSS_SHA_384",
        "RSASSA_PSS_SHA_512",
        "RSASSA_PKCS1_V1_5_SHA_256",
        "RSASSA_PKCS1_V1_5_SHA_384",
        "RSASSA_PKCS1_V1_5_SHA_512",
        "ECDSA_SHA_256",
        "ECDSA_SHA_384",
        "ECDSA_SHA_512",
        "SM2DSA",
        "ML_DSA_SHAKE_256",
        "ED25519_SHA_512",
    }
)


def _validate_configuration(*, key_id: str, signing_algorithm: str) -> tuple[str, str]:
    normalized_key_id = key_id.strip()
    normalized_algorithm = signing_algorithm.strip().upper()
    if not normalized_key_id:
        raise ValueError("AWS KMS key_id is required")
    if normalized_algorithm not in AWS_KMS_SIGNING_ALGORITHMS:
        raise ValueError("unsupported AWS KMS signing algorithm")
    return normalized_key_id, normalized_algorithm


def _validate_raw_message(message: bytes) -> None:
    if not isinstance(message, bytes) or not message:
        raise ValueError("AWS KMS message must be non-empty bytes")
    if len(message) > _MAX_RAW_MESSAGE_BYTES:
        raise ValueError(
            "AWS KMS RAW message exceeds 4096 bytes; pre-hashed DIGEST mode must be an explicit adapter decision"
        )


class AwsKmsSigner(WorkloadSigner):
    """AWS KMS-backed workload signer with no private-key material in-process.

    `client` is intentionally duck-typed to the boto3 KMS client surface. This
    keeps boto3 optional for TrustKernel core while production deployments can
    inject a real boto3 client configured through their normal AWS credential
    chain and IAM/KMS key policy.
    """

    def __init__(self, *, client: Any, key_id: str, signing_algorithm: str):
        self._client = client
        self._key_id, self._algorithm = _validate_configuration(
            key_id=key_id,
            signing_algorithm=signing_algorithm,
        )

    @property
    def key_reference(self) -> str:
        return f"aws-kms:{self._key_id}"

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def sign(self, message: bytes) -> bytes:
        _validate_raw_message(message)
        response = self._client.sign(
            KeyId=self._key_id,
            Message=message,
            MessageType="RAW",
            SigningAlgorithm=self._algorithm,
        )
        signature = response.get("Signature") if isinstance(response, dict) else None
        if not isinstance(signature, (bytes, bytearray)) or not signature:
            raise ValueError("AWS KMS Sign returned an invalid signature")
        return bytes(signature)


class AwsKmsVerifier(WorkloadVerifier):
    """AWS KMS Verify adapter paired with :class:`AwsKmsSigner`."""

    def __init__(self, *, client: Any, key_id: str, signing_algorithm: str):
        self._client = client
        self._key_id, self._algorithm = _validate_configuration(
            key_id=key_id,
            signing_algorithm=signing_algorithm,
        )

    @property
    def key_reference(self) -> str:
        return f"aws-kms:{self._key_id}"

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def verify(self, message: bytes, signature: bytes) -> bool:
        _validate_raw_message(message)
        if not isinstance(signature, bytes) or not signature:
            return False
        response = self._client.verify(
            KeyId=self._key_id,
            Message=message,
            MessageType="RAW",
            Signature=signature,
            SigningAlgorithm=self._algorithm,
        )
        return bool(response.get("SignatureValid")) if isinstance(response, dict) else False
