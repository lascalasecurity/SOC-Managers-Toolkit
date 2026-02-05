# SecOps Agents Overview

This lab runs a small fleet of reasoning-first SecOps agents, each backed by MCP tools (Purple MCP, TI Aggregator) and (optionally) JS helpers for data collection. This document describes their roles, schedules, tooling, and artifacts.

> **Jarvis (orchestrator)** keeps these agents healthy, tunes their prompts based on SOC Manager feedback and direct observation, and maintains helper scripts and wiring.

---

## 1. Security Analyst

**Purpose:**
- Monitor SentinelOne Purple alerts.
- Triage and prioritize alert queues.
- Enrich relevant IOCs with TI.
- Recommend concrete, non-destructive next actions.

**Schedule:**
- Cron job: `security-lab:security-analyst:30m`
- Every 30 minutes (`*/30 * * * *`, America/Los_Angeles).
- **Quiet hours:** 20:00–04:30 PT.
  - During quiet hours: responds with `NO_REPLY` and does not run checks.
  - Outside quiet hours: always runs and always produces a chat summary.

**Reasoning agent (cron payload):**
- Type: `agentTurn` (isolated session).
- Responsibilities per run:
  1. Refresh or load current alerts (prefer via helper, see below).
  2. Triage and prioritize new/recently updated alerts (3–5 top ones).
  3. Deepen context: `get_alert`, `get_alert_notes`, optionally `get_alert_history`.
  4. Extract IOCs (IP/domain/url/hash/CVE) from alert context.
  5. Enrich key IOCs with TI (`ti-aggregator.enrich_indicator`, `cve_report`).
  6. Assess risk and produce concrete recommendations.
  7. Emit a concise chat summary + detailed `report.md`.

**Helper script:**
- Path: `agents/security-analyst/runner.js`
- Mode: `--mode collect`
- Behavior:
  - Calls `purple-mcp.list_alerts first=50` via MCPorter.
  - Writes raw alerts snapshot to:
    - `artifacts/cron/security-analyst/<STAMP>/alerts.json`
      - `<STAMP>` ≈ `YYYYMMDD-HHMM` in PT.
  - Prints: `Collected alerts to artifacts/cron/security-analyst/<STAMP>/alerts.json`.
  - Does **no** IOC extraction or TI in `collect` mode.

**Artifacts (expected):**
- Directory pattern: `artifacts/cron/security-analyst/<YYYYMMDD-HHMM>/`
- Files (agent-driven; some optional):
  - `alerts.json` — base view of alerts (from helper or direct Purple calls).
  - `focused_alerts.json` — subset of alerts deeply triaged.
  - `enrichment.json` — TI lookups and decisions.
  - `report.md` — detailed narrative.

---

## 2. Vulnerability Manager

**Purpose:**
- Understand current vulnerability posture.
- Reason about risk beyond numeric scores.
- Produce a prioritized remediation plan.

**Schedule:**
- Cron job: `security-lab:vuln-manager:daily-0700`
- Daily at 07:00 PT.

**Reasoning agent (cron payload):**
- Type: `agentTurn` (isolated session).
- Responsibilities per run:
  1. Refresh/load current vulnerability snapshot (prefer via helper).
  2. Compare against `last.json` to detect **meaningful** changes:
     - New vulns.
     - Severity/status/exploitability changes (KEV/exploited/EPSS).
  3. Build risk-based prioritized list (10–15 items): severity, KEV, EPSS, asset context, fix availability.
  4. Group vulns where remediation can be batched (same CVE/product across hosts).
  5. Use `ti-aggregator.cve_report` selectively on top CVEs.
  6. Recommend remediation actions and timelines (e.g., 24–48h / this week / backlog).
  7. Emit chat summary + `report.md`.

**Helper script:**
- Path: `agents/vuln-manager/runner.js`
- Mode: `--mode collect`
- Behavior:
  - Calls `purple-mcp.list_vulnerabilities first=100`.
  - Writes raw snapshot to:
    - `artifacts/cron/vuln-manager/<YYYYMMDD>/vulnerabilities.raw.json`
  - Prints: `Collected vulnerabilities to artifacts/cron/vuln-manager/<YYYYMMDD>/vulnerabilities.raw.json`.
  - No scoring, diffs, or TI in `collect` mode.

**Artifacts (expected):**
- Directory pattern: `artifacts/cron/vuln-manager/<YYYYMMDD>/`
- Files:
  - `vulnerabilities.raw.json` — raw snapshot used.
  - `prioritized.json` — structured ranked list + groupings.
  - `changes.json` — new/changed/resolved vs `last.json`.
  - `report.md` — detailed narrative.
- State file:
  - `artifacts/cron/vuln-manager/last.json` — previous summarized snapshot for diffing.

---

## 3. Threat Intelligence Analyst (TI Digest)

**Purpose:**
- Track external threats.
- Decide what’s relevant for this environment.
- Feed both the human and other agents (especially hunters) with curated intel.

**Schedule:**
- Cron job: `security-lab:ti-digest:daily-0500`
- Daily at 05:00 PT.

**Reasoning agent (cron payload):**
- Type: `agentTurn` (isolated session).
- Responsibilities per run:
  1. Build a **curated snapshot** of relevant threats (ransomware, infostealers, APT, critical CVEs, C2 infra) using `ti-aggregator` tools.
  2. Decide relevance for this lab (Windows endpoints like Frontier-PHX, Jean-Luc Picard, etc.).
  3. Produce `digest.md` (10–15 bullets) explaining:
     - What each threat is.
     - Why it matters (or doesn’t) here.
     - Key indicators (CVE, domains, IPs, hashes).
  4. Generate 3–5 Purple-tuned **hunt ideas** for Threat Hunter / Proactive Hunter.
  5. Produce `ti_iocs.json` as a machine-consumable IOC feed for other agents.
  6. Emit a concise chat summary + “For other agents” hints.

**Artifacts (expected):**
- Directory pattern: `artifacts/cron/ti-digest/<YYYYMMDD>/`
- Files:
  - `digest.md` — human TI digest.
  - `ti_iocs.json` — structured IOC feed with fields like:
    - `indicator` (string)
    - `type` (`ip`, `domain`, `url`, `hash`, `cve`)
    - `threatContext` (campaign/family/issue)
    - `relevance` (`high` / `medium` / `low` for this environment)

---

## 4. Threat Hunter (Environment-Driven)

**Purpose:**
- Reactive hunting.
- Use environment alerts + context to look for follow-on compromise or lateral movement.
- Scoped to **threats already seen in alerts**.

**Schedule:**
- Cron job: `security-lab:threat-hunter:weekly-mon-0800`
- Weekly, Mondays at 08:00 PT.

**Reasoning agent (cron payload):**
- Type: `agentTurn` (isolated session).
- Responsibilities per run:
  1. Refresh alert snapshot for last ~7 days (prefer via helper).
  2. Derive 2–5 **alert-driven hypotheses**, e.g.:
     - Lateral movement based on specific alerts.
     - Credential theft following mimikatz/infostealer detections.
     - Additional C2 or malware activity from alerted hosts.
  3. For relevant alerts:
     - Use `get_alert`, `get_alert_notes`, `get_alert_history`.
     - Extract IOCs and behavior context.
  4. Use `purple_ai` + `powerquery` to design & run hunts that operationalize these hypotheses over the last 7 days (or narrower where appropriate).
  5. Interpret results: no evidence, weak suspicion, or strong evidence.
  6. Emit chat summary + detailed `report.md` and JSONs.

**Helper script:**
- Path: `agents/threat-hunter/runner.js`
- Mode: `--mode collect`
- Behavior:
  - Calls `get_timestamp_range hours=168` to define a 7-day window.
  - Calls `list_alerts first=100`, then filters alerts into that window.
  - Writes snapshot to:
    - `artifacts/cron/threat-hunter/<YYYYMMDD>/alerts.raw.json` with:
      ```json
      {
        "window": { "start_timestamp": ..., "end_timestamp": ... },
        "alerts": [ ... ]
      }
      ```
  - Prints: `Collected alerts snapshot to artifacts/cron/threat-hunter/<YYYYMMDD>/alerts.raw.json`.
  - No IOC extraction, TI, or PQ in `collect` mode.

**Artifacts (expected):**
- Directory pattern: `artifacts/cron/threat-hunter/<YYYYMMDD>/`
- Files:
  - `alerts.raw.json` — 7-day alerts snapshot (from helper).
  - `hypotheses.json` — alert-driven hypotheses + rationale.
  - `powerqueries.json` — PowerQueries executed, mapped to hypotheses.
  - `results.json` or per-query result files — hunt outputs.
  - `report.md` — narrative report on what was hunted and what was found.

**Separation from Proactive Hunter:**
- Threat Hunter is **reactive** (alerts-based).
- Proactive Threat Hunter is **TI-driven** (new external IOCs, even without alerts).

---

## 5. Proactive Threat Hunter (TI-Driven)

**Purpose:**
- Proactive hunting on **new TI-driven IOCs**.
- Translate TI into hunts against the environment, even before alerts exist.

**Schedule:**
- Cron job: `security-lab:proactive-threat-hunter:weekly-mon-0800`
- Weekly, Mondays at 08:00 PT.

**Reasoning agent (cron payload):**
- Type: `agentTurn` (isolated session).
- Responsibilities per run:
  1. Use TI (`ti-aggregator`) and/or TI Digest’s `ti_iocs.json` to select a set of high-value IOCs (CVE/domain/IP/url/hash).
  2. Decide which IOCs to hunt on (10–20 max) and why.
  3. Use `purple_ai` to convert each IOC into one or more PowerQueries (hunt for exploitation/behavior in last 7 days).
  4. Execute those PowerQueries via `powerquery`.
  5. Interpret results and provide recommendations.
  6. Emit chat summary and write artifacts:
     - `ti.json` / `ti_iocs.json` (as used).
     - `powerqueries.json`, `powerquery_*.json`.
     - `report.md`.

_(JS helper behavior for Proactive Hunter may evolve as we add IOC normalization helpers.)_

---

## 6. SOC Manager

**Purpose:**
- Meta-agent for **weekly SecOps overview** and **cross-agent QA/fact-checking**.
- Sits above the five domain agents.

**Schedule:**
- Cron job: `security-lab:soc-manager:weekly-overview`
- Weekly, Mondays at 09:00 PT.

**Reasoning agent (cron payload):**
- Type: `agentTurn` (isolated session).
- Responsibilities per run:
  1. Gather latest outputs from:
     - Security Analyst → `artifacts/cron/security-analyst/<STAMP>/`
     - TI Analyst → `artifacts/cron/ti-digest/<YYYYMMDD>/`
     - Vuln Manager → `artifacts/cron/vuln-manager/<YYYYMMDD>/`
     - Threat Hunter → `artifacts/cron/threat-hunter/<YYYYMMDD>/`
     - Proactive Hunter → `artifacts/cron/proactive-hunter/<YYYYMMDD>/`
  2. Summarize each agent’s state:
     - Alert posture, TI themes, vuln risk posture, hunt coverage.
  3. Fact-check & QA:
     - Cross-check agents’ conclusions against their raw data and each other.
     - Flag and correct unsupported conclusions, missed signals, and inconsistencies.
  4. Produce a **SOC Weekly Overview**:
     - `overview.md` under `artifacts/cron/soc-manager/<YYYYMMDD>/` with sections:
       1. Executive Summary.
       2. Alert & Incident Posture.
       3. Threat Intelligence Overview.
       4. Vulnerability Risk Posture.
       5. Hunt Coverage.
       6. Cross-Agent QA & Corrections.
       7. Recommended Priorities for Next Week.
  5. Emit chat summary:
     - Top 3–7 executive bullets.
     - Any important corrections.
     - Path to `overview.md`.

**Role in tuning:**
- Jarvis (orchestrator) treats SOC Manager’s QA as the **primary signal** for agent tuning.
- When SOC Manager identifies issues, Jarvis updates prompts, helper behavior, or schemas accordingly, while also considering direct observations and your feedback.

---

## Orchestrator (Jarvis)

- Monitors:
  - Cron job health and schedules.
  - Agent chat outputs and artifacts.
  - SOC Manager weekly QA findings.
- Tunes:
  - Agent prompts and behaviors to reduce repeated QA issues.
  - Helper scripts to keep data collection deterministic and efficient.
- Evolves:
  - New helpers, schemas, and dashboards.
  - Separation of duties (alert-driven vs TI-driven vs summarization).

This document should stay aligned with actual wiring in `config/`, cron jobs, and helper scripts. Update it whenever we add agents, change schedules, or significantly adjust behaviors.