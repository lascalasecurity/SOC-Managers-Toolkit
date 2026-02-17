#!/usr/bin/env node
import path from 'node:path';
import fs from 'node:fs';

import { mcporterCall } from '../../lib/mcporter.js';
import { extractIOCs } from '../../lib/ioc.js';
import { scoreAlert } from '../../lib/score.js';
import { ensureDir, writeJson, writeText } from '../../lib/fs.js';

const CWD = process.env.SECURITY_LAB_CWD || process.cwd();
const TZ = 'America/Los_Angeles';

function nowParts() {
  const d = new Date();
  const stamp = d
    .toLocaleString('sv-SE', { timeZone: TZ })
    .replace(' ', 'T')
    .slice(0, 16)
    .replace(/[:T-]/g, '');
  // sv-SE yields YYYY-MM-DD HH:MM:SS; we want YYYYMMDD-HHMM
  const iso = d.toLocaleString('sv-SE', { timeZone: TZ });
  const [date, time] = iso.split(' ');
  const [hh, mm] = time.split(':');
  return { ymd: date.replaceAll('-', ''), hhmm: `${hh}${mm}`, stamp: `${date.replaceAll('-', '')}-${hh}${mm}` };
}

function inQuietHours(date = new Date()) {
  // Quiet: 20:00-04:30 PT inclusive
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: TZ,
    hour12: false,
    hour: '2-digit',
    minute: '2-digit'
  }).formatToParts(date);
  const hh = Number(parts.find((p) => p.type === 'hour')?.value ?? '0');
  const mm = Number(parts.find((p) => p.type === 'minute')?.value ?? '0');
  const mins = hh * 60 + mm;
  const qStart = 20 * 60;
  const qEnd = 4 * 60 + 30;
  return mins >= qStart || mins <= qEnd;
}

async function main() {
  const mode = process.argv.includes('--mode') ? process.argv[process.argv.indexOf('--mode') + 1] : 'collect';
  const started = new Date();

  const quiet = inQuietHours(started);

  const { stamp } = nowParts();
  const outDir = path.join(CWD, 'artifacts', 'cron', 'security-analyst', stamp);
  ensureDir(outDir);

  // 1) list alerts (collector behavior is always the first step)
  const list = await mcporterCall({
    cwd: CWD,
    tool: 'purple-mcp.list_alerts',
    // NOTE: purple-mcp.list_alerts currently fails when passed pagination args like `first`.
    // Rely on the server default page size instead.
    args: {},
    output: 'json',
    timeoutMs: 120000
  });

  const listJson = JSON.parse(list.stdout);
  writeJson(path.join(outDir, 'alerts.json'), listJson);

  if (mode === 'collect') {
    // In collect mode we stop after fetching and normalizing alerts.
    // Reasoning agents will read alerts.json and perform triage/analysis themselves.
    process.stdout.write(quiet ? 'NO_REPLY' : `Collected alerts to ${path.relative(CWD, outDir)}/alerts.json\n`);
    return;
  }

  // Quiet hours: collect-only (no enrichment/chat) to keep the dashboard fresh without paging.
  if (quiet) {
    process.stdout.write('NO_REPLY');
    return;
  }

  const edges = listJson?.edges ?? [];
  const nodes = edges.map((e) => e.node).filter(Boolean);
  const newAlerts = nodes.filter((n) => String(n.status).toUpperCase() === 'NEW');

  // Sort by severity rank then most recent detected
  const sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0, UNKNOWN: -1 };
  newAlerts.sort((a, b) => {
    const sa = sevRank[String(a.severity || 'UNKNOWN').toUpperCase()] ?? -1;
    const sb = sevRank[String(b.severity || 'UNKNOWN').toUpperCase()] ?? -1;
    if (sb !== sa) return sb - sa;
    return String(b.detected_at || b.detectedAt || '').localeCompare(String(a.detected_at || a.detectedAt || ''));
  });

  const top = newAlerts.slice(0, 3);

  // 2) fetch details + notes, extract IOCs, enrich
  const enriched = [];
  for (const a of top) {
    const alertId = a.id;

    const detail = await mcporterCall({
      cwd: CWD,
      tool: 'purple-mcp.get_alert',
      args: { alert_id: alertId },
      output: 'json',
      timeoutMs: 120000
    });
    const detailJson = JSON.parse(detail.stdout);

    let notesJson = null;
    if (detailJson?.note_exists || detailJson?.noteExists) {
      const notes = await mcporterCall({
        cwd: CWD,
        tool: 'purple-mcp.get_alert_notes',
        args: { alert_id: alertId },
        output: 'json',
        timeoutMs: 120000
      });
      notesJson = JSON.parse(notes.stdout);
    }

    const fullText = [
      a.name,
      a.description,
      JSON.stringify(detailJson),
      notesJson ? JSON.stringify(notesJson) : ''
    ].filter(Boolean).join('\n');

    const iocs = extractIOCs(fullText).slice(0, 5);

    const ti = [];
    for (const ioc of iocs) {
      const r = await mcporterCall({
        cwd: CWD,
        tool: 'ti-aggregator.enrich_indicator',
        args: { indicator: ioc.indicator, type: ioc.type },
        output: 'json',
        timeoutMs: 120000
      });
      ti.push(JSON.parse(r.stdout));
    }

    const score = scoreAlert({ alert: a, tiFindings: ti });

    enriched.push({
      alert: {
        id: a.id,
        severity: a.severity,
        status: a.status,
        name: a.name,
        detectedAt: a.detected_at || a.detectedAt,
        asset: a.asset?.name || a.asset?.id || null
      },
      iocs,
      ti,
      score
    });

    writeJson(path.join(outDir, `alert_${alertId}.detail.json`), detailJson);
    if (notesJson) writeJson(path.join(outDir, `alert_${alertId}.notes.json`), notesJson);
  }

  writeJson(path.join(outDir, 'enriched.json'), { newCount: newAlerts.length, top: enriched });

  // 3) chat summary
  let md = '';
  md += `Security Analyst (30m) — ${stamp} PT\n`;
  md += `NEW alerts: ${newAlerts.length} (fetched ${nodes.length})\n\n`;

  if (!enriched.length) {
    md += `No NEW alerts to triage.\n`;
  } else {
    md += `Top alerts:\n`;
    for (const item of enriched) {
      md += `- [${item.alert.severity}] ${item.alert.name} — ${item.alert.asset ?? 'unknown asset'} — score ${item.score}/100\n`;
      md += `  id: ${item.alert.id} detectedAt: ${item.alert.detectedAt}\n`;
      if (item.iocs.length) {
        md += `  IOCs: ${item.iocs.map((x) => `${x.type}:${x.indicator}`).join(', ')}\n`;
        const bad = item.ti.filter((t) => t.verdict === 'malicious' || t.verdict === 'suspicious');
        if (bad.length) md += `  TI flags: ${bad.map((t) => `${t.type}:${t.indicator}=${t.verdict}`).join(', ')}\n`;

        // AbuseIPDB-specific context for IPs, when present
        const abuseLines = [];
        for (const t of item.ti) {
          if (t.type !== 'ip' || !t.scores) continue;
          const score = typeof t.scores.abuseipdb === 'number' ? t.scores.abuseipdb : null;
          if (score == null || score <= 0) continue;
          const repEvidence = (t.evidence || []).filter((e) => e.source === 'abuseipdb');
          const reports = repEvidence.find((e) => e.kind === 'reports')?.value;
          const lastRep = repEvidence.find((e) => e.kind === 'last_reported_at')?.value;
          abuseLines.push(`    - ${t.indicator}: AbuseIPDB confidence ${score}` +
            (typeof reports === 'number' ? ` (${reports} reports)` : '') +
            (lastRep ? `, last reported ${lastRep}` : ''));
        }
        if (abuseLines.length) {
          md += '  AbuseIPDB:\n' + abuseLines.join('\n') + '\n';
        }
      }
      md += `  Next: review alert notes; ask Purple AI for PQ to validate + scope on this host; run PQ for last 24h.\n`;
    }
  }

  md += `\nArtifacts: ${path.relative(CWD, outDir)}/ (alerts.json, enriched.json, per-alert detail/notes)\n`;

  writeText(path.join(outDir, 'summary.md'), md);
  process.stdout.write(md);
}

main().catch((err) => {
  process.stderr.write(String(err?.stack || err) + '\n');
  process.stdout.write(`Security Analyst: ERROR\n${String(err?.message || err)}\n`);
  process.exitCode = 1;
});
