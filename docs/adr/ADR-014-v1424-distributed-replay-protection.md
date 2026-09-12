# ADR-014: Distributed replay protection for signed workload envelopes

Status: Accepted

## Context

TrustKernel workload signature envelopes bind a nonce, purpose, bounded lifetime, message digest, attestation digest, key reference, and signing algorithm. A nonce only prevents replay when every verifier that accepts the envelope shares a consistent single-use state.

The prior callback contract also evaluated the nonce before cryptographic verification. In a deployment where checking a nonce consumes it, a forged envelope could therefore burn a legitimate nonce before the signature was proven valid.

RFC 9449 describes replay protection for DPoP proofs by retaining unique proof identifiers for the proof validity window, and explicitly notes that deployments with multiple servers need shared state. TrustKernel uses the same defensive pattern for its own signed workload-envelope protocol; it does not claim protocol equivalence with DPoP.

Redis supports an atomic `SET` operation with `NX` and expiry, which gives the required one-winner single-use primitive without a read-then-write race.

## Decision

1. TrustKernel validates structure, bounded lifetime, purpose/key/algorithm bindings, message digest, attestation metadata/digest, expected workload identity, and the cryptographic signature before consuming replay state.
2. Replay nonces are limited to 256 characters and SHA-256 hashed before persistence. Raw nonces are not used as Redis keys.
3. `InMemoryReplayGuard` remains available for local, offline, test, and Judge Mode use.
4. `RedisReplayGuard` is the first-party multi-replica adapter. It consumes a nonce using one atomic Redis `SET key value NX EX ttl` operation.
5. Replay-state TTL is bounded to 300 seconds, matching the maximum TrustKernel workload-signature envelope lifetime.
6. Redis errors propagate to the caller; production verification must fail closed rather than silently downgrade to process-local replay state.
7. The production readiness gate requires `TRUSTKERNEL_REPLAY_BACKEND=redis` and a TLS `rediss://` shared Redis endpoint.
8. CI exercises two independent replay-guard instances against live Redis and proves that only the first consumption succeeds.

## Security boundaries

- This mechanism prevents reuse of a TrustKernel envelope nonce only when verification is actually configured with the replay guard.
- The Redis service itself must be access-controlled, monitored, backed by secure transport, and operated as trusted security state.
- SHA-256 hashing reduces exposure of nonce values in storage and constrains key shape; it is not encryption.
- SPIFFE-shaped identifiers remain metadata until the deployment adapter cryptographically validates the provider's SVID/token and trust bundle.
- This control is not evidence of production security accuracy, certification, or universal replay resistance outside TrustKernel's signed-envelope boundary.

## Consequences

Production deployments gain deterministic cross-replica single-use enforcement without changing offline/Judge Mode ergonomics. Verification ordering prevents invalid signatures from poisoning replay state, and CI makes the distributed behavior a release contract rather than an undocumented deployment assumption.

## References

- RFC 9449, OAuth 2.0 Demonstrating Proof of Possession (DPoP), replay prevention guidance: https://www.rfc-editor.org/rfc/rfc9449
- Redis `SET` command (`NX` and expiry options): https://redis.io/docs/latest/commands/set/
