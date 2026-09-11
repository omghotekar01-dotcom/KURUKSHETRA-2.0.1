# Security Research Prompt

Research the current state of autonomous-agent security specifically for decisions that can change TrustKernel architecture or evaluation.

Prioritize primary/authoritative sources: OWASP Agentic guidance/ACS, NIST agent identity/authorization, current Model Context Protocol authorization/security specifications, OpenTelemetry GenAI semantic conventions, original papers and benchmark repositories.

For every finding, record:

1. Threat or failure mode.
2. Why existing TrustKernel controls do or do not cover it.
3. Proposed runtime control or architecture change.
4. Required data/evidence fields.
5. Test/benchmark case to add.
6. Product/UX impact.
7. Trade-offs and residual risk.
8. Primary source and date/version.

Reject vague recommendations such as “use AI to detect attacks” unless the detection role, failure behavior and deterministic fallback are specified. Security-critical authorization should remain external to the agent model wherever practical.

End with a prioritized implementation list ranked by security value, startup value, hackathon demo value, implementation risk and dependency cost.
