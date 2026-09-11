# ADR-009: Distributed quota backend contract and native OpenTelemetry export

Status: Accepted for v1.4.3

## Context

TrustKernel's workspace rate/quota guard was process-local. That is correct for offline demos and single-process development, but multiple API workers would each maintain independent counters. The result is not a safe production quota boundary unless quota accounting is coordinated atomically across workers.

TrustKernel also already emitted OpenTelemetry-shaped OTLP/HTTP JSON without an OpenTelemetry runtime dependency. That path is useful for deterministic demos, but production deployments benefit from the official OpenTelemetry Python SDK and exporter ecosystem.

## Decision

### Quota backend

Keep the in-memory sliding-window implementation as the zero-configuration default. Introduce a `QuotaBackend` contract whose `check_and_consume` operation receives the effective limits and timestamp and MUST perform the limit decision and increment atomically for a workspace.

Provide a provider-neutral callback adapter so deployments can bind Redis/Lua, transactional SQL, DynamoDB, or a managed rate-limit service without putting a vendor dependency in TrustKernel core. Backend results are schema-validated before they are surfaced through the gateway. TrustKernel annotates responses with the backend name and whether it is distributed.

The callback contract deliberately does not pretend that a remote implementation is safe merely because it is remote: atomicity is an explicit requirement of the backend contract.

### OpenTelemetry

Retain the dependency-light OTLP/HTTP JSON bridge for offline and deterministic use. Add an opt-in `send_native()` path using the official OpenTelemetry Python SDK plus the OTLP HTTP trace exporter. Persisted TrustKernel security events are converted into SDK spans with original event timestamps and TrustKernel/GenAI attributes.

Use `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` when present and keep `TRUSTKERNEL_OTLP_HTTP_ENDPOINT` as a compatibility fallback. Native export uses `force_flush` before reporting a successful local SDK flush. This is not represented as proof that the downstream observability backend retained the data.

## Rationale and current references

OpenTelemetry recommends OTLP exporters for preserving the OpenTelemetry data model and recommends using the Collector in production deployments. The Python SDK provides standard span processors/exporters, and batching is generally recommended for continuously running services. TrustKernel currently uses a simple processor in the explicit historical-event export helper to keep one-shot export behavior deterministic; a long-running auto-instrumented deployment may separately use the standard batched pipeline.

Authoritative references reviewed for this change:

- OpenTelemetry Python exporters: https://opentelemetry.io/docs/languages/python/exporters/
- OpenTelemetry Python: https://opentelemetry.io/docs/languages/python/
- OpenTelemetry Python zero-code configuration: https://opentelemetry.io/docs/zero-code/python/

Dependency versions are pinned in `backend/requirements.txt` for reproducible CI.

## Consequences

- Existing offline behavior remains available with no external quota service.
- Multi-worker deployments now have an explicit integration boundary for atomic global quotas.
- Native OTLP export becomes a first-class option without removing the existing lightweight JSON exporter.
- A concrete Redis or other distributed backend remains deployment-specific and should include concurrency/failure-mode tests before being advertised as production-ready.
- Benchmark outputs remain synthetic regression/security-utility measurements and must not be described as production security accuracy.
