# ADR-018 — AgentDojo native evidence import boundary

## Status
Accepted for the v1.4.28 integration checkpoint.

## Context
TrustKernel already supports an AgentDojo-inspired interchange adapter for running imported attack/benign plans through the TrustKernel policy engine. That adapter intentionally does not claim native AgentDojo utility or targeted security metrics because those depend on the upstream task environment, attack injection, traces and task-specific validators.

AgentDojo remains a useful external benchmark source, but its API is explicitly under development and upstream scoring semantics/edge cases can change across releases. Native evidence therefore needs a provenance-preserving ingestion path rather than a lossy conversion into TrustKernel decision metrics.

## Decision
Add `backend/app/benchmarks/agentdojo_native.py` as a separate native-result importer/report builder.

The importer:

- accepts common result wrappers (`results`, `records`, `runs`, `cases`, `evaluations`);
- records suite, user task, injection task, attack, defense, model and trace reference;
- preserves upstream `utility` and `security` validator booleans as-is;
- computes deterministic SHA-256 identity over normalized rows;
- reports grouped true-rates only as upstream-validator summaries;
- rejects malformed/unscored rows rather than guessing missing semantics;
- never relabels upstream security values as TrustKernel attack block rate, production accuracy, certification or guaranteed real-world protection.

The report explicitly states that native metrics are not recomputed. Reproduction requires the recorded AgentDojo version/commit and its upstream task validators.

## Rationale
The official AgentDojo project describes a benchmark that evaluates tool-using agents across suites/tasks and warns that its package API may change. Its benchmark depends on suite-specific tasks and scoring logic. A pass-through evidence adapter keeps those results auditable without pretending TrustKernel can infer native semantics from a generic JSON export.

## Consequences

- External benchmark evidence becomes easier to archive, compare and include in judge/research reports.
- TrustKernel maintains a hard boundary between its deterministic runtime decisions and upstream benchmark validators.
- A future version may add explicit adapters for a pinned AgentDojo release once the exact export schema is locked and regression fixtures are vendored or generated in CI.
