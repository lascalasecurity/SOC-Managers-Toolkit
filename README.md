# Jarvis SecOps Lab (security-lab)

A local-only SecOps lab built for **autonomous security operations**:
- Reasoning-first agents (triage, TI, vuln mgmt, hunting, SOC Manager QA)
- Deterministic helper collectors that write durable artifacts
- A standalone interactive HTML dashboard that updates as new runs land

## What you get

- **MCP stack (via MCPorter)**
  - `purple-mcp` (SentinelOne Purple)
  - `ti-aggregator` (local Node MCP for enrichment + feed snapshots)
- **Agents (conceptual)**
  - Security Analyst (30m)
  - TI Digest (daily)
  - Vulnerability Manager (daily)
  - Threat Hunter + Proactive Threat Hunter (weekly)
  - SOC Manager (weekly overview + QA)
- **Artifacts-first workflow**
  - Everything writes to `artifacts/cron/<agent>/<run>/...`
  - Dashboard reads those artifacts (no dependence on chat delivery)

## Quick start

1) Install deps:
```bash
npm install
```

2) Configure keys (local-only):
```bash
cp mcp/.env.local.example mcp/.env.local
# edit mcp/.env.local and add your keys
```

3) Smoke test MCP:
```bash
set -a && source mcp/.env.local && set +a
npx -y mcporter --config config/mcporter.json list-tools
npx -y mcporter --config config/mcporter.json call purple-mcp.list_alerts first=1
```

4) Run the dashboard:
```bash
npm run dashboard
# http://127.0.0.1:18888
```

## Docs

- `docs/AGENTS.md` — roles, schedules, artifact contracts
- `docs/SETUP.md` — clone-and-run instructions (keys, smoke tests, dashboard)
- `docs/ARCHITECTURE-diagram.html` — point-in-time architecture diagram

## Security / secrets

- **Never commit keys.** Local files are gitignored:
  - `mcp/.env.local`
  - `mcp/servers.local.json`
  - `artifacts/**`, `runs/**`, `logs/**`
