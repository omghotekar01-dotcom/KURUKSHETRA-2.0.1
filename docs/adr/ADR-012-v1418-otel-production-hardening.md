# ADR-012 — v1.4.18 OpenTelemetry production hardening

## Status

Accepted for the v1.4.18 checkpoint.

## Context

TrustKernel already had two telemetry export paths: a dependency-light OTLP/HTTP JSON bridge and a native OpenTelemetry Python SDK exporter. The native exporter was useful, but three release-quality gaps remained:

1. telemetry resource/scope metadata still hard-coded an old `1.4.3` service version;
2. the native path did not honor the standard `OTEL_EXPORTER_OTLP_ENDPOINT` fallback when the trace-specific endpoint was absent; and
3. production readiness only recommended configuring telemetry—it did not reject a configured plaintext OTLP endpoint.

OpenTelemetry's OTLP exporter specification defines `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` as signal-specific and higher precedence than the global `OTEL_EXPORTER_OTLP_ENDPOINT`. For OTLP/HTTP, a global base endpoint is expanded to the trace path `/v1/traces`. The specification also states that the `https` scheme indicates a secure connection. OpenTelemetry's Python exporter documentation recommends OTLP exporters for interoperability with Collectors/backends.

Authoritative references reviewed for this decision:

- OpenTelemetry OTLP exporter specification: https://opentelemetry.io/docs/specs/otel/protocol/exporter/
- OpenTelemetry Python exporters documentation: https://opentelemetry.io/docs/languages/python/exporters/

## Decision

1. Read `service.version` and instrumentation-scope version from the repository's canonical `VERSION` file instead of maintaining an independent telemetry version literal.
2. Resolve the native trace endpoint in this order:
   - explicit method argument;
   - `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`;
   - `OTEL_EXPORTER_OTLP_ENDPOINT` plus `/v1/traces`;
   - TrustKernel's compatibility `TRUSTKERNEL_OTLP_HTTP_ENDPOINT`.
3. Preserve HTTP collectors for local/development and Judge Mode workflows.
4. When `TRUSTKERNEL_ENV=production`, both telemetry export paths fail closed before network I/O unless the configured endpoint is an absolute HTTPS URL.
5. Keep telemetry optional for production readiness, but make insecure transport a blocking error whenever an endpoint is configured.
6. Add release-integrity and deterministic-manifest coverage so stale telemetry version literals or removal of the production HTTPS guard block a future stable checkpoint.

## Consequences

- Offline/demo behavior remains compatible with local collectors such as `http://127.0.0.1:4318`.
- Production deployments can omit telemetry without failing the deployment gate, but cannot configure plaintext export and still be considered ready.
- Telemetry emitted by different TrustKernel releases can be correlated to the actual canonical repository release rather than a stale embedded version.
- The HTTPS requirement protects transport confidentiality/integrity expectations; it does **not** prove that a Collector, backend, credential, or deployment is secure.

## Evidence boundary

This change is a configuration/runtime hardening measure, not a security certification. Likewise, TrustKernel benchmark and Judge Mode outputs remain regression/evaluation evidence and must not be represented as production security accuracy.
