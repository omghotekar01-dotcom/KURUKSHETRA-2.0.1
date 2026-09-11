# Research Basis

TrustKernel is intentionally research-driven. Architecture decisions should be tied to primary standards/research where possible, then translated into code, tests and explicit trade-offs.

## Current anchors

- **OWASP Agentic Applications Top 10 / Agent Control Standard** — motivates runtime control hooks, inspectability, traceability, agentic threat coverage and portable policy enforcement.
- **NIST software/AI-agent identity and authorization work** — motivates distinct agent identities, least privilege, authorization, auditing and non-repudiation.
- **Model Context Protocol authorization guidance** — motivates canonical resource binding, scope minimization, no token passthrough and server trust/provenance controls.
- **OpenTelemetry GenAI semantic/observability work** — motivates standardized traces for agent/model/tool activity.
- **AgentDojo-style security evaluation** — motivates evaluating task utility and attack resistance together rather than reporting only attack blocking.
- **Information-flow-control and security-aware planning research** — motivates deterministic confidentiality/integrity labels, causal dependencies, safe repair and selective human approval.

## Primary URLs

- https://genai.owasp.org/
- https://genai.owasp.org/resource/agent-control-standard-acs/
- https://csrc.nist.gov/
- https://modelcontextprotocol.io/specification/
- https://opentelemetry.io/docs/specs/semconv/gen-ai/
- https://arxiv.org/abs/2406.13352

## Research-to-product rule

Do not add a paper citation merely to make the project look advanced. Every research item should answer at least one of:

- What threat does this reveal?
- What runtime control should change?
- What data/evidence should be recorded?
- What benchmark/test should be added?
- What product decision becomes more defensible?

## Honest claims

The bundled attack lab is synthetic and deterministic. It is useful for regression and demos, but it is not a substitute for external benchmark evaluation, red teaming or production validation.
