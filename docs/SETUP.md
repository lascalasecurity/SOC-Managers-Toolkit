# Setup (Security Lab)

This repo is intended to be **clone-and-run** for a local SecOps lab built around:
- OpenClaw (cron scheduler + reasoning agents)
- MCPorter (tool router)
- SentinelOne Purple MCP (purple-mcp)
- Local TI Aggregator MCP (ti-aggregator)
- A standalone local dashboard (HTML + small API server)

## 0) Prereqs

- Node.js 22+
- npm 10+
- OpenClaw installed and running on the same host (Gateway)
- `uvx` available (used to launch `purple-mcp` via stdio)

## 1) Automated / agent-friendly bootstrap

If you have an OpenClaw agent (or are comfortable running a shell script) on the target host, you can bootstrap the lab in one shot:

```bash
# On the target host
bash -c "curl -sSf https://raw.githubusercontent.com/lascalasecurity/Jarvis-secops/main/scripts/bootstrap.sh -o /tmp/secops-bootstrap.sh && chmod +x /tmp/secops-bootstrap.sh && /tmp/secops-bootstrap.sh"
```

What this does:
- Clones the repo into `~/security-lab` (or uses it if already cloned).
- Runs `npm install`.
- Creates `mcp/.env.local` with commented placeholders (you must edit with your own keys).
- Installs a user-level systemd service for the dashboard and enables it.
- Attempts to apply the bundled OpenClaw cron config from `docs/cron-jobs.json`.

After the script finishes:
- Edit `~/security-lab/mcp/.env.local` with your API keys/URLs.
- Hit `http://127.0.0.1:18888` to confirm the dashboard.
- If OpenClaw is installed, run `openclaw cron list` and confirm the `security-lab:*` jobs are present.

---

## 2) Manual clone (if you prefer to do it yourself)


```bash
git clone git@github.com:lascalasecurity/Jarvis-secops.git security-lab
cd security-lab
npm install
```

## 3) Configure secrets (DO NOT COMMIT)

All secrets are local-only.

1) Copy the env template:

```bash
cp mcp/.env.local.example mcp/.env.local
```

2) Fill in keys in `mcp/.env.local`:

- `PURPLEMCP_CONSOLE_BASE_URL`
- `PURPLEMCP_CONSOLE_TOKEN`
- `OTX_API_KEY`
- `VIRUSTOTAL_API_KEY`
- optional: `GREYNOISE_API_KEY`, `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`, `URLSCAN_API_KEY`, `ABUSECH_API_KEY`

This file is gitignored (`mcp/.env.local`).

## 4) Validate MCP connectivity (smoke tests)

```bash
set -a && source mcp/.env.local && set +a

# list servers
npx -y mcporter --config config/mcporter.json list

# list tools
npx -y mcporter --config config/mcporter.json list-tools

# quick Purple call
npx -y mcporter --config config/mcporter.json call purple-mcp.list_alerts first=1

# quick TI feed snapshot (KEV + OTX pulses)
npx -y mcporter --config config/mcporter.json call ti-aggregator.fetch_feed_snapshot sources=kev sources=otx limit=5 days=7
```

## 5) Run helper collectors (deterministic)

```bash
set -a && source mcp/.env.local && set +a

node agents/security-analyst/runner.js --mode collect
node agents/vuln-manager/runner.js --mode collect
node agents/threat-hunter/runner.js --mode collect
node agents/ti-analyst/runner.js --mode collect --limit 100
```

Artifacts land under:
- `artifacts/cron/<agent>/<stamp>/...`

## 6) Run the dashboard (local-only)

```bash
npm run dashboard
```

Default: `http://127.0.0.1:18888`

The dashboard watches `artifacts/cron/**` and updates live.

## 7) OpenClaw cron jobs

This repo assumes you will create OpenClaw cron jobs to run the **reasoning agents** on a schedule.

Reference:
- `docs/AGENTS.md` (roles, schedules, artifacts)

Important:
- Cron isolated runs may not automatically have your env loaded.
- Any shell command inside a cron run that needs MCP keys should prefix:

```bash
cd /path/to/security-lab && set -a && source mcp/.env.local && set +a && <command>
```

(We recommend baking this instruction into each cron job prompt.)
