Orchestrator Overview

Responsibilities
- Intake tasks (CLI or file drop)
- Plan: translate task into a DAG of MCP tool calls
- Execute: call MCP servers, collect outputs, handle retries
- Enforce policy: allowlists, budgets, human gates
- Record: structured logs, audit trail, artifacts
- Report: synthesize findings into markdown/HTML

MVP Interfaces
- Input: ./runs/queue/*.json (task specs) or CLI shim
- Output: ./runs/<run-id>/{plan.json, log.jsonl, artifacts/}

Task Spec (example)
{
  "intent": "baseline inventory",
  "inputs": {"scope": "org:acme"},
  "constraints": {"timeBudgetMin": 10, "readOnly": true}
}

Plan Node (example)
{
  "id": "n1",
  "tool": "security-platform:list_assets",
  "params": {"scope": "org:acme"},
  "provides": ["assets"],
  "retries": 2,
  "timeoutMs": 20000
}

Policy Gates
- readOnly true → block tools tagged as mutating
- scope allowlist → restrict tenant/site ids
- budget → cap total tool calls / runtime
