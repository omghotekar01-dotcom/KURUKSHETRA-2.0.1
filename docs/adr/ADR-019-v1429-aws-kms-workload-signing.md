# ADR-019: AWS KMS workload-signing adapter

## Status

Accepted for TrustKernel v1.4 production-hardening line.

## Context

TrustKernel already defines provider-neutral `WorkloadSigner` and `WorkloadVerifier` boundaries and binds workload attestation metadata, key reference, algorithm, purpose, lifetime, nonce, and message digest into the signed workload envelope. The remaining gap was a concrete production adapter demonstrating how a managed asymmetric signing service can satisfy that boundary without placing private-key material inside the TrustKernel process.

AWS KMS `Sign` and `Verify` support asymmetric KMS keys with `SIGN_VERIFY` usage. AWS requires the signing key and signing algorithm to be recorded for verification and distinguishes `RAW` message input from `DIGEST` input. For `RAW`, KMS performs the algorithm-defined hashing; for `DIGEST`, callers must provide a correctly sized pre-hash. AWS documents a 4096-byte maximum for RAW message input.

SPIFFE Workload API remains complementary rather than interchangeable with KMS. SPIFFE provides workload identity/SVID material and trust bundles; TrustKernel continues to represent that identity as attestation metadata while external signing custody is supplied by a signer adapter.

## Decision

Add `AwsKmsSigner` and `AwsKmsVerifier` in `backend/app/services/kms_signing.py`.

The adapter:

- injects a KMS-compatible client instead of importing or configuring `boto3` in TrustKernel core;
- never accepts or returns private-key material;
- uses explicit `MessageType="RAW"` for both Sign and Verify;
- fails closed for messages above 4096 bytes instead of silently switching to `DIGEST` semantics;
- uses an explicit allow-list of asymmetric KMS signing algorithms;
- binds the configured KMS key identifier into the existing workload-envelope `key_reference` as `aws-kms:<key-id>`;
- relies on the existing v2 envelope lifetime, nonce, purpose, attestation, algorithm, digest, and replay-validation controls.

A deployment wanting pre-hashed `DIGEST` mode must implement it as an explicit future adapter decision because digest construction is algorithm-sensitive and accidental double hashing can break verification or weaken assumptions.

## Consequences

Production deployments may inject a real AWS SDK KMS client using their normal AWS credential chain, IAM policy, and KMS key policy. Tests use a deterministic fake client and therefore require no AWS credentials or network calls.

This adapter demonstrates an external-key-custody integration boundary. It does not claim that AWS KMS, SPIFFE, or TrustKernel automatically establishes production security accuracy, hardware attestation, or end-to-end workload trust without correct deployment policy and infrastructure.

## Authoritative references

- AWS KMS API: Sign — https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html
- AWS KMS API: Verify — https://docs.aws.amazon.com/kms/latest/APIReference/API_Verify.html
- SPIFFE Workload API — https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/
