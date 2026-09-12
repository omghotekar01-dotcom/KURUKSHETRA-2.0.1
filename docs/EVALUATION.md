# Evaluation Plan

TrustKernel must be evaluated on **security and utility together**. A guard that blocks everything is not a useful agent-security product.

## Core metrics

- Attack control rate: attack-labelled cases resulting in BLOCK or REQUIRE_APPROVAL.
- Attack escape rate: attack-labelled cases that remain execution-permitting. This is a TrustKernel decision metric, **not** AgentDojo targeted ASR.
- Benign completion rate: benign-labelled cases that remain executable.
- False positive rate: benign actions incorrectly restricted.
- Expected-outcome rate: deterministic regression cases that produce one of their declared expected decisions.
- Approval routing accuracy: cases sent to the correct human gate.
- Repair proposal rate / repair success: unsafe plans safely transformed while preserving user intent.
- Autonomy rate: legitimate tasks completed without human intervention.
- Enforcement latency: incremental runtime decision time.
- Policy coverage: proportion of target threat classes represented by explicit controls.

For binomial attack-control and benign-completion rates, the external-report adapter also emits 95% Wilson intervals. These intervals describe uncertainty in the imported benchmark sample only; they do not convert that sample into a production-security accuracy estimate.

## Bundled regression suite

`backend/benchmark.py` runs deterministic scenarios repeatedly to detect runtime regressions. The scenarios cover OWASP Agentic threat classes plus TrustKernel-specific operational controls.

The suite is a **regression harness**, not proof of general real-world security accuracy. Never present synthetic 100% expected-outcome performance as a claim that TrustKernel stops 100% of attacks.

## AgentDojo-inspired external bridge

`app/benchmarks/adapter.py` accepts provider-neutral JSON and preserves common AgentDojo-style provenance dimensions:

- suite
- model
- attack
- defense
- user task id
- injection task id
- trace reference
- dataset/run provenance

Supported collection wrappers include `cases`, `results`, `tasks`, `runs`, and `records`. The importer rejects malformed plans and duplicate case IDs and fingerprints the normalized dataset with SHA-256.

Reports include:

- attack-control and attack-escape rates for attack-labelled cases;
- benign-completion and false-positive rates for benign-labelled cases;
- 95% Wilson intervals;
- decision counts and execution latency;
- breakdowns by source, suite, model, attack, and defense;
- coverage counts for task IDs, injection IDs, and trace references;
- a SHA-256 digest of the normalized result rows.

### Important AgentDojo boundary

AgentDojo evaluates agent task utility and attack success inside its own dynamic task environments. Its published results distinguish metrics such as utility, utility under attack, and targeted attack success rate, and its maintainers explicitly caution that the public result table is not a fair universal leaderboard because not every model/defense/attack combination is evaluated.

TrustKernel therefore **does not infer AgentDojo native utility or targeted ASR from TrustKernel policy decisions**. Native AgentDojo metrics require the upstream environment, task validators, attacks, defenses, and trajectories. TrustKernel's bridge is an importer/evaluator for runtime-governance evidence, not a replacement for upstream benchmark execution.

Authoritative references used for this evaluation contract:

- AgentDojo repository: https://github.com/ethz-spylab/agentdojo
- AgentDojo results documentation: https://agentdojo.spylab.ai/results/

## Release gate

A stable checkpoint should not be promoted to `main` unless:

1. Core tests pass.
2. Judge Mode produces contrasting BLOCK / REWRITE / APPROVAL / benign outcomes.
3. Audit-chain verification passes.
4. Enterprise default policy validates.
5. External benchmark imports retain provenance and reject malformed records.
6. Benchmark reports preserve the evidence boundary and do not silently relabel TrustKernel decision metrics as native AgentDojo ASR/utility.
7. No benchmark regression is represented as production security accuracy or certification.
