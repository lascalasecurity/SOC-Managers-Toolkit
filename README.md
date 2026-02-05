Autonomous Security Lab (ASL)

Goal
- Stand up an orchestrated swarm of agents (LLM + tool-using) to run SecOps tasks end-to-end: recon, detection, response, hardening, reporting.
- Operate entirely on this sandboxed host; no extra container/VM layers. Primary capability surface is an external security-platform MCP server plus local utilities.

High-level Phases
1) Foundations
   - Define threat model, trust boundaries, and RBAC.
   - Connect to the security-platform MCP server; add local utility MCPs (fs/http/git).
   - Establish event bus, runbook format, and logging.
2) Orchestration MVP
   - Single-tenant workflow: task intake → plan → execute with MCP tools → report.
   - Human-in-the-loop checkpoints.
3) Autonomy & Scale
   - Multi-agent choreography (planner, operators, reporter).
   - Scheduling, SLAs, retries, rollbacks.
4) Safety & Policy
   - Policy enforcement, egress guards (via MCP allowlists/policies).
   - Secrets, attestation, drift detection.
5) Integrations
   - Asset inventory, ticketing, alerting, dashboards (when external hooks are permitted).

Key Properties
- Deterministic where possible (versioned tools, pinned models, seeds).
- Observable: structured logs, spans, audit trails, artifacts.
- Reproducible: runbooks + env snapshots.
- Safe-by-default: least privilege, outbound allowlists.

Quick Start (proposed)
- ./docs/ARCHITECTURE.md → target topology
- ./docs/RUNBOOKS/* → YAML workflows
- ./orchestrator/* → agent router + guardrails
- ./mcp/* → MCP server configs

Next: see TODO.md for immediate asks.
