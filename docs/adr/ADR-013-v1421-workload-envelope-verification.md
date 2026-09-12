# ADR-013: Workload signature envelope verification and replay bounds

Status: Accepted for v1.4.21

## Context

TrustKernel v1.4.2 introduced provider-neutral workload attestation metadata and external signing adapters so private keys can remain in SPIFFE/SPIRE, KMS, HSM, or another deployment integration. The first envelope format signed purpose, issue time, message digest, and attestation digest, but left the outer key reference and algorithm outside the signed binding and did not define an envelope expiry, nonce, or provider-neutral verifier contract.

That is too weak for a production-facing portable envelope. A verifier must be able to prove which external key reference and algorithm the signer intended, reject stale envelopes, and integrate replay state without requiring TrustKernel core to own provider credentials.

SPIFFE defines SVIDs as cryptographically verifiable workload identity documents and supplies SVIDs plus trust bundles through the Workload API. AWS KMS signing guidance likewise requires recording the KMS key and signing algorithm for verification and recommends limiting the time for which a signature is effective, including a timestamp in signed data where appropriate.

## Decision

TrustKernel emits `trustkernel.workload-signature.v2` envelopes.

The canonical signed binding now includes:

- envelope version;
- purpose;
- issue and expiry timestamps;
- a nonce;
- SHA-256 of the application message;
- SHA-256 of the workload attestation metadata;
- external key reference; and
- signing algorithm identifier.

Envelope lifetime is bounded to at most 300 seconds and is clipped to the attestation expiry when the underlying attestation expires sooner. Callers may supply a nonce or allow TrustKernel to generate a cryptographically random URL-safe nonce.

A provider-neutral `WorkloadVerifier` interface and `CallbackVerifier` adapter complement `WorkloadSigner`. Verification fails closed on unsupported versions, stale/future timestamps, invalid lifetime, message/attestation digest mismatch, unexpected purpose/workload identity, key-reference or algorithm mismatch, rejected nonce, malformed signature encoding, or provider verification failure.

The optional nonce validator is intentionally supplied by the deployment integration. Production deployments can connect it to their shared replay store; TrustKernel core does not pretend an in-process set is sufficient for multi-replica replay protection.

## Security boundaries

- TrustKernel still does not require custody of external private keys.
- A SPIFFE-shaped URI in metadata is not treated as proof of a valid SVID. Certificate/token validation and trust-bundle validation remain provider/deployment responsibilities.
- A KMS/HSM key reference is metadata until the provider-backed signature verifies.
- The envelope proves integrity of the bound fields when verification succeeds; it is not an attestation authority or a security certification.
- JWT-SVID replay characteristics are not hidden by this envelope. Where architecture permits, SPIFFE recommends X.509-SVIDs over bearer-style JWT-SVIDs.

## Compatibility

The previous v1 envelope remains historical evidence only. New envelope generation emits v2. Verification deliberately accepts v2 only so callers do not silently downgrade to the weaker binding.

## Authoritative references

- SPIFFE Workload API specification: https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/
- SPIFFE concepts and SVID guidance: https://spiffe.io/docs/latest/spiffe/concepts/
- SPIFFE working with SVIDs: https://spiffe.io/docs/latest/deploying/svids/
- AWS KMS Sign API: https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html
- AWS KMS Verify API: https://docs.aws.amazon.com/kms/latest/APIReference/API_Verify.html
