# Evaluation Plan

TrustKernel must be evaluated on **security and utility together**. A guard that blocks everything is not a useful agent-security product.

## Core metrics

- Attack control rate: malicious cases resulting in BLOCK, REWRITE or REQUIRE_APPROVAL as expected.
- Benign completion rate: legitimate tasks that remain executable.
- False positive rate: benign actions incorrectly restricted.
- False negative rate: malicious actions incorrectly allowed.
- Approval routing accuracy: cases sent to the correct human gate.
- Repair proposal rate / repair success: unsafe plans safely transformed while preserving user intent.
- Autonomy rate: legitimate tasks completed without human intervention.
- Enforcement latency: incremental runtime decision time.
- Policy coverage: proportion of target threat classes represented by explicit controls.

## Bundled regression suite

`backend/benchmark.py` runs 19 deterministic scenarios × 10 iterations by default. The scenarios cover OWASP Agentic ASI01–ASI10 plus TrustKernel-specific operational controls.

The suite is a **regression harness**, not proof of general real-world security accuracy. Never present synthetic 100% expected-outcome performance as a claim that TrustKernel stops 100% of attacks.

## External evaluation direction

The adapter in `app/benchmarks/adapter.py` accepts task/security cases in a simple JSON format so external benchmark suites can be mapped into TrustKernel without changing the runtime. A future bridge should support realistic agent-task benchmarks such as AgentDojo-style evaluations and report both task utility and attack success.

## Release gate

A stable checkpoint should not be promoted to `main` unless:

1. Core tests pass.
2. Judge Mode produces contrasting BLOCK / REWRITE / APPROVAL / benign outcomes.
3. Audit-chain verification passes.
4. Enterprise default policy validates.
5. No benchmark regression is silently relabeled as a real-world security claim.
