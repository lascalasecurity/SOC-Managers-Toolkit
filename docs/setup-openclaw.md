# SecOps Lab — OpenClaw Setup Guide

Goal: make this repo deployable on any machine running OpenClaw so your agent can spin up the full SecOps lab (agents, crons, dashboard) with minimal human glue.

This assumes you already have:
- OpenClaw installed and running
- Node.js (v22.x recommended) and npm available on the host

---

## 1. Clone the repo into the OpenClaw workspace

On the machine where OpenClaw runs:

```bash
cd ~/.openclaw/workspace
git clone <REPO_URL> security-lab
cd security-lab
```

If you prefer a different folder name, set `SECURITY_LAB_CWD` accordingly when running commands.

---

## 2. Install Node dependencies

From the `security-lab` directory:

```bash
npm install
```

This installs dependencies for the dashboard and any helper scripts.

---

## 3. Configure MCP / TI environment

### 3.1 mcporter config

This lab uses `mcporter` to talk to two MCP servers:

- `purple-mcp` — SentinelOne Purple (Singularity)
- `ti-aggregator` — local Threat Intelligence aggregator in `mcp/ti-aggregator/`

A portable config is already committed at:

- `config/mcporter.json`

If you need to customize it for your environment, use:

- `config/mcporter.json.example` as a reference.

### 3.2 TI and Purple secrets

Create your local env file from the template:

```bash
cd ~/.openclaw/workspace/security-lab
cp mcp/.env.local.example mcp/.env.local
```

Then edit `mcp/.env.local` and fill in at least:

- `PURPLEMCP_CONSOLE_BASE_URL` — your SentinelOne Purple console URL
- `PURPLEMCP_CONSOLE_TOKEN` — API token for Purple MCP
- `VIRUSTOTAL_API_KEY` — VirusTotal key
- `OTX_API_KEY` — AlienVault OTX key

Optional providers (fill in as needed):

- `GREYNOISE_API_KEY`
- `ABUSECH_API_KEY`
- `ABUSEIPDB_API_KEY`
- `SHODAN_API_KEY`
- `URLSCAN_API_KEY`
- `GITHUB_PAT`

These are loaded at runtime via:

```bash
cd "$SECURITY_LAB_CWD" && set -a && source mcp/.env.local && set +a && <YOUR_COMMAND>
```

---

## 4. Install required OpenClaw skills

The lab expects **ClawSec Suite** to be installed so it can monitor skills and gate removals.

From the host (outside the repo), install:

```bash
openclaw skills install clawsec-suite
```

See `docs/required-skills.md` for details. Other skills are optional.

---

## 5. Apply the SecOps cron topology

Cron jobs live in the OpenClaw Gateway scheduler, but this repo contains the **source of truth** for them:

- `config/gateway-cron.json` — declarative cron spec
- `config/cron/*.prompt.txt` — per-job prompts

### 5.1 Tell your agent to apply the spec

From a chat with your OpenClaw agent, you can say something like:

> "Use the `security-lab` repo and apply its cron spec (config/gateway-cron.json) to the Gateway."

Under the hood, the agent should:

1. Run the helper to emit the spec:

   ```bash
   cd ~/.openclaw/workspace/security-lab
   node scripts/apply-cron-spec.mjs
   ```

2. Read the resulting JSON and for each job:
   - If missing in `cron.list` → create it via `cron.add` using:
     - `schedule` from the spec
     - `payload` built from `messageFile` + model/timeout
     - `delivery` from the spec
   - If present → optionally update it if the spec changed.

Once applied, you should see jobs like:

- `security-lab:security-analyst:30m`
- `security-lab:ti-digest:daily-0500`
- `security-lab:proactive-threat-hunter:collector-daily-0505`
- `security-lab:vuln-manager:daily-0700`
- `security-lab:threat-hunter:weekly-mon-0800`
- `security-lab:soc-manager:daily-0830`
- `security-lab:soc-manager:weekly-overview`

A future improvement is a dedicated automation script that calls the Gateway `cron` tool directly, but this is enough for an agent-driven deployment.

---

## 6. Start the SecOps dashboard (optional but recommended)

From the `security-lab` directory:

```bash
npm run dashboard
```

Then open:

- `http://127.0.0.1:18888`

The dashboard will auto-discover artifacts under:

- `artifacts/cron/security-analyst/...`
- `artifacts/cron/vuln-manager/...`
- `artifacts/cron/ti-digest/...`
- `artifacts/cron/threat-hunter/...`
- `artifacts/cron/proactive-hunter/...`
- `artifacts/cron/soc-manager/...`

and render per-agent tiles and reports.

---

## 7. Environment variable: SECURITY_LAB_CWD

To make everything path-agnostic, this lab prefers you set:

```bash
export SECURITY_LAB_CWD="/path/to/your/security-lab"
```

If unset, scripts usually fall back to `process.cwd()`; setting it explicitly makes prompts and shell snippets accurate.

You can add this to your shell profile or set it in any environment where you run lab commands.

---

## 8. Sanity checks after deployment

Once everything is in place:

1. **Cron runs**
   - After the next scheduled windows (or by manually triggering jobs), confirm artifacts are being written under `artifacts/cron/...`.

2. **Security Analyst**
   - Check that `security-analyst` runs every 30 minutes and writes `alerts.json`.

3. **TI Digest + Proactive Hunter**
   - Ensure `ti-digest/<YYYYMMDD>/ti_iocs.json` exists.
   - Ensure `proactive-hunter/<YYYYMMDD>/ti_iocs.selected.json` is created by the collector.

4. **Dashboard**
   - Verify tiles show the latest runs and no stray `test` runs are present.

If any of these fail, the likely culprits are:

- Missing or incorrect `mcp/.env.local`
- `config/mcporter.json` not matching your environment
- Cron jobs not applied (check with the Gateway `cron.list` tool)

---

With these steps, another OpenClaw user should be able to:

1. Clone this repo,
2. Install deps,
3. Drop in their env keys,
4. Install ClawSec,
5. Ask their agent to apply `config/gateway-cron.json`,

and end up with the same SecOps lab you’re running now.
