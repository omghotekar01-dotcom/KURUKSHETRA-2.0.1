# ADR-008: Workload attestation metadata and external signing adapters

Status: Accepted for v1.4.2

## Context

TrustKernel already supports Ed25519 workload identities and replay-resistant signed agent messages. The next production step is to avoid assuming that private keys live inside the TrustKernel process and to preserve enough workload provenance to bind signatures to a concrete runtime identity.

SPIFFE's Workload API is designed to let workloads obtain identities and related cryptographic material without baking workload credentials into the application. AWS KMS and comparable HSM/KMS systems expose signing operations in which the caller references a managed asymmetric key instead of exporting the private key.

## Decision

TrustKernel adds a provider-neutral `WorkloadAttestation` metadata object and a `WorkloadSigner` adapter boundary.

The attestation object records only public provenance metadata: provider, workload identity, issue/expiry times, selectors, and an optional external evidence reference. SPIFFE/SPIRE-shaped identities must use a valid `spiffe://` URI. Expired or future-dated attestations fail closed.

`WorkloadSigner` exposes only a key reference, algorithm identifier and `sign(message)` operation. The built-in `CallbackSigner` allows deployments to bridge a SPIFFE client, cloud KMS, HSM, or another signer without importing that provider SDK into TrustKernel core and without handing TrustKernel a private key.

An attested signature envelope signs a canonical binding containing purpose, timestamp, message SHA-256 and attestation SHA-256. The raw application message is not embedded in the signing request produced by the envelope helper.

## Security properties

- TrustKernel does not require custody of external workload private keys.
- Signatures are cryptographically bound to attestation metadata by digest.
- Expired and malformed SPIFFE-style attestations are rejected.
- Provider-specific SDKs remain optional integration-layer dependencies.
- A key reference is metadata, not proof of possession; proof comes from the external signing operation and downstream verification.

## Non-goals

This checkpoint does not claim to implement the SPIFFE Workload API protocol, node/workload attestation plugins, cloud IAM authorization, certificate path validation, or production HSM/KMS verification. Those remain adapter/deployment responsibilities.

## Authoritative references

- SPIFFE Workload API specification: https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/
- SPIFFE guidance for working with SVIDs: https://spiffe.io/docs/latest/deploying/svids/
- AWS KMS Sign API: https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html
- AWS KMS Verify API: https://docs.aws.amazon.com/kms/latest/APIReference/API_Verify.html
