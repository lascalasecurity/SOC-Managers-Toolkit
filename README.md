# SOC Manager’s Toolkit

A **local-only** SecOps lab for *autonomous security operations*:

- Reasoning-first agents (triage, TI, vuln mgmt, hunting, SOC Manager QA)
- Deterministic collectors that write durable artifacts (JSON/MD)
- A standalone dashboard that updates as new runs land

> Design goal: **artifacts-first observability**. Chat delivery is “nice to have”; the source of truth is `artifacts/cron/...`.

---

## What you get

### Agents (roles)
- **Security Analyst** (every 30m): alert snapshot + triage
- **TI Analyst (TI Digest)** (daily): curated TI + IOCs
- **Vulnerability Manager** (daily): vuln posture snapshot + prioritized fixes
- **Threat Hunter** (daily/weekly depending on your cron config): environment-driven hunts
- **Proactive Threat Hunter** (daily/weekly depending on your cron config): TI-driven hunts
- **SOC Manager** (daily + weekly): executive summary + cross-agent QA
- **Janitor** (daily): artifact retention/cleanup

### Integrations (MCP via MCPorter)
- `purple-mcp` — SentinelOne Purple
- `ti-aggregator` — local Node MCP for enrichment + feed snapshots

### Dashboard
- Local web UI: `http://127.0.0.1:18888`
- Reads from: `artifacts/cron/<agent>/<run>/...`

---

## Fastest setup (OpenClaw)

If you’re running this **inside OpenClaw**, use the OpenClaw-native path:

*Tip* : Give your OpenClaw agent this Repo URL. It should be able to handle everything from there. You may need to help guide it, and you will need to provide keys, but all the instructions are geared for your OpenClaw agent to follow.

1) Follow: `docs/setup-openclaw.md`
2) Verify required skills: `docs/required-skills.md`
3) Validate host health:

```bash
npm run doctor
```

This is the **source of truth** setup path.

---

## Manual setup (non-OpenClaw)

### Prereqs
- Node.js (LTS recommended)
- `npm install`
- SentinelOne Purple + TI credentials (stored locally)

### 1) Install dependencies
```bash
npm install
```

### 2) Configure keys (local-only)
```bash
cp mcp/.env.local.example mcp/.env.local
# edit mcp/.env.local and add your keys
```

### 3) Smoke test MCP connectivity
```bash
set -a && source mcp/.env.local && set +a
npx -y mcporter --config config/mcporter.json list-tools
npx -y mcporter --config config/mcporter.json call purple-mcp.list_alerts first=1
```

### 4) Run the dashboard
```bash
npm run dashboard
# http://127.0.0.1:18888
```

### 5) (Optional) Apply scheduled jobs
Cron job definitions live at:
- `docs/cron-jobs.json`

How you apply these depends on your scheduler/runtime (OpenClaw Gateway cron vs system cron). If you’re using OpenClaw, follow `docs/setup-openclaw.md`.

---

## Repo map (where to look)

- `agents/` — collectors + agent runners
- `artifacts/cron/` — **all outputs** (dashboard reads from here)
- `dashboard/` — local dashboard server + static UI
- `config/` — MCPorter config + cron prompt templates
- `docs/` — setup + architecture + agent contracts
- `scripts/` — janitor / health / utility scripts

---

## Docs (recommended reading order)

1) `docs/setup-openclaw.md` — best path if you’re using OpenClaw
2) `docs/SETUP.md` — clone-and-run instructions (keys, smoke tests, dashboard)
3) `docs/AGENTS.md` — roles, schedules, artifact contracts
4) `docs/ARCHITECTURE.md` + `docs/ARCHITECTURE-diagram.html` — how the pieces fit

---

## Security / secrets

- **Never commit keys.** Local files are gitignored:
  - `mcp/.env.local`
  - `mcp/servers.local.json`
  - `artifacts/**`, `runs/**`, `logs/**`

---

## Legacy bootstrap (discouraged)

An older “curl | bash” bootstrap flow exists for reference, but it’s not the preferred setup path:

- `docs/setup-openclaw.md` is the supported route.
