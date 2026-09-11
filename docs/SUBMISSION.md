# Submission Copy

## Project title
TrustKernel — Runtime Safety Kernel for Autonomous AI Agents

## One-line pitch
An execution firewall that intercepts autonomous AI actions and allows, rewrites, escalates, or blocks them before they can cause unsafe real-world side effects.

## Problem
AI agents are moving from text generation to tool use: email, files, databases, APIs, code repositories, cloud infrastructure, MCP servers and payments. Prompt-level guardrails alone cannot reliably enforce what actions are actually permitted.

## Solution
TrustKernel introduces a model-independent runtime boundary using workspace/agent identity, user-intent authorization, causal action graphs, sensitive-data taint tracking, deterministic policies, risk/consequence analysis, safe plan repair, human approval gates and hash-chained evidence.

## Differentiator
Instead of only asking whether an input prompt looks malicious, TrustKernel asks whether the **planned sequence of side effects** is authenticated, authorized and safe.

## Demo
- Blocks a prompt-injection chain attempting secret exfiltration.
- Blocks a poisoned/untrusted MCP tool.
- Rewrites destructive analytics SQL into a read-only operation.
- Escalates a simulated high-value payment for human approval.
- Allows a benign analytics workflow to demonstrate utility preservation.

## Technology
Python, FastAPI, Pydantic, SQLite, Ed25519 workload identities, deterministic policy/risk engines, local attack simulations, HTML/CSS/JavaScript dashboard and Python SDK.

## Safety
All risky integrations in the hackathon MVP are deterministic local simulations.
