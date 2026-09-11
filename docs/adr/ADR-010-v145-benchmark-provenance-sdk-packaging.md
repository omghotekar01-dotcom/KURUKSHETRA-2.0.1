# ADR-010 — v1.4.5 Benchmark Provenance and SDK Packaging

## Status
Accepted for v1.4.5 candidate.

## Context
TrustKernel already exposed a small AgentDojo-style benchmark bridge, but external datasets can vary in wrapper names, labeling, suite metadata, and versioning. A single aggregate score is also easy to over-interpret. Current agent-security research continues to emphasize separate security and utility measurements, realistic/adaptive attacks, and benchmark limitations rather than treating one benchmark number as deployment assurance.

The Python guards also existed as source files but had no standard package metadata, making installation less reproducible for judges and adopters.

## Decision
1. Keep the existing `trustkernel.benchmark.v2` report schema identifier for compatibility, while adding `report_format_version = 3` for the richer representation.
2. Add a provider-neutral dataset importer accepting list payloads or `cases` / `results` / `tasks` wrappers.
3. Normalize common attack/benign labels without claiming exact compatibility with every AgentDojo release.
4. Reject malformed and duplicate cases explicitly instead of silently counting them.
5. Attach SHA-256 dataset identity plus source, suite and dataset-version provenance.
6. Report breakdowns by source, suite, attack and defense while preserving separate attack-block, false-negative, benign-completion and false-positive metrics.
7. Carry an explicit warning that imported/synthetic results are evaluation evidence, not production security accuracy, certification, or guarantee.
8. Package the Python SDK with PEP 621 metadata, bounded `httpx` dependency, a typed-package marker, and repository-install instructions.

## Research basis
- AgentDojo established a security/utility benchmark for tool-using agents and indirect prompt injection.
- Later work has highlighted that agent-security benchmarks can saturate, contain weak attacks, or mislead when metrics are incomplete; therefore TrustKernel treats benchmark provenance and dimensional reports as first-class evidence.
- AgentDyn (2026) further motivates dynamic/open-ended evaluation and avoiding claims that static benchmark performance alone represents real-world security.

## Consequences
- Existing v1.3 consumers that assert the v2 report schema remain compatible.
- New reports are easier to audit, segment and reproduce.
- Upstream benchmark adapters can be added later without contaminating the core report contract.
- The SDK becomes installable with normal Python packaging tooling while remaining intentionally lightweight.
