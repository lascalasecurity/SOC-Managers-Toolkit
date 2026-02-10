# Required OpenClaw Skills for `security-lab`

This lab expects a few skills to be installed in the OpenClaw Gateway so the agents can work end-to-end.

## ClawSec Suite

**Skill:** `clawsec-suite`

- Purpose: monitors installed skills for advisories, flags potentially malicious or deprecated skills, and provides a human-in-the-loop kill switch.
- How this lab uses it:
  - A Gateway cron job (`ClawSec Advisory Scan`) periodically asks ClawSec to scan skills.
  - When ClawSec recommends removal, the main agent will *ask for your approval* before any removal/disable.

**Install (example):**

```bash
# From the machine where OpenClaw is installed
openclaw skills install clawsec-suite
```

> Note: exact install syntax may vary by OpenClaw version; see https://docs.openclaw.ai for the latest.

## Other skills

The core SecOps lab (Security Analyst, TI Analyst, Vuln Manager, Threat Hunter, Proactive Hunter, SOC Manager) is implemented as **local agents + JS runners** inside this repo and does **not** depend on additional OpenClaw skills.

However, you may want to install additional skills for your own workflows (e.g., cloud providers, ticketing integrations). Those are optional and not required for the lab to function.

## MCP vs Skills

Separate from OpenClaw skills, this lab also expects two MCP servers to be reachable via `mcporter`:

- `purple-mcp` — SentinelOne Purple (Singularity) MCP
- `ti-aggregator` — local Threat Intelligence aggregator under `mcp/ti-aggregator/`

These are configured in `config/mcporter.json`. They are **not** OpenClaw skills, but external MCP tools.
