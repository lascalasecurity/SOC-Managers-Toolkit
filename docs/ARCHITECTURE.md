Autonomous Security Lab – Architecture

Actors
- Human Operator (A)
- Orchestrator (Jarvis): planner, router, policy enforcer, auditor
- Agents: planner-agent, operator-agents (specialized), reporter-agent
- MCP Servers: primary tool surface (security platform integration + local utilities)
- Subsystems: message bus, artifact store, policy engine

Topology (MVP)
- Command intake → Planner → Execution Graph (DAG) → Operators (via MCP) → Artifacts → Reporter
- Message bus (local) with topics: tasks, plans, actions, observations, alerts
- Storage: ./artifacts (evidence), ./logs (JSONL), ./runs (manifests)

Execution Environment
- Run everything locally on this sandboxed host; no additional container/VM layers
- Outbound access constrained by MCP server/tool policies and allowlists

Policies & Guardrails
- Allowlist of MCP tools and target resources per workflow phase
- Rate limits and budget caps (API, time, $$)
- Human-in-the-loop required for high-risk actions (e.g., destructive changes)

Observability
- Structured logs + trace ids per run
- Audit trail combining prompts, tool calls, outputs, decisions
- Metrics: task latency, success rate, coverage, drift

Runbooks (YAML)
- name, intent, inputs, constraints
- steps (planner-exec sequence), gates, fallbacks
- outputs (artifacts, tickets, reports)

MCP Inventory (initial)
- security-platform MCP (primary)
- fs (scoped to workspace)
- http(s) fetcher with domain allowlist
- git (read-only initially)

Threat Model (draft)
- Assume orchestrator compromised if it can exfiltrate secrets; minimize secret material
- Agent prompt injection via untrusted content; sanitize inputs, signature prompts, tool responses
- Supply-chain risk in MCP servers; pin versions, verify hashes

Open Questions
- MCP server details: endpoint(s), tool list/schema, auth method, rate limits
- Message bus: lightweight (files/JSONL) vs NATS/Redis (only if needed later)
- Reporting surface: local HTML/PDF vs tickets (when external hooks are allowed)
