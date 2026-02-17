#!/usr/bin/env node
import path from 'node:path';

import { ensureDir, writeJson, writeText } from '../../lib/fs.js';
import { listAlerts, getAlert, getAlertNotes, getTimestampRange, purpleAi } from '../../lib/purple.js';
import { extractIOCs } from '../../lib/ioc.js';
import { bulkEnrich } from '../../lib/ti.js';

const CWD = process.env.SECURITY_LAB_CWD || process.cwd();
const TZ = 'America/Los_Angeles';

function ymdNow() {
  const d = new Date();
  const iso = d.toLocaleString('sv-SE', { timeZone: TZ });
  return iso.split(' ')[0].replaceAll('-', '');
}

async function main() {
  const mode = process.argv.includes('--mode') ? process.argv[process.argv.indexOf('--mode') + 1] : 'collect';
  const ymd = ymdNow();
  const outDir = path.join(CWD, 'artifacts', 'cron', 'threat-hunter', ymd);
  ensureDir(outDir);

  // last 7 days (168h) by default
  const range = await getTimestampRange({ cwd: CWD, hours: 24 * 7 });

  // get_timestamp_range may return either:
  // - { start_timestamp, end_timestamp } (ms)
  // - { offset_time, current_time } (ISO strings)
  const startMs =
    typeof range?.start_timestamp === 'number' ? range.start_timestamp :
    range?.offset_time ? new Date(range.offset_time).getTime() :
    Date.now() - 24 * 7 * 60 * 60 * 1000;

  const endMs =
    typeof range?.end_timestamp === 'number' ? range.end_timestamp :
    range?.current_time ? new Date(range.current_time).getTime() :
    Date.now();

  const window = {
    ...range,
    start_timestamp: startMs,
    end_timestamp: endMs,
    start_time: new Date(startMs).toISOString(),
    end_time: new Date(endMs).toISOString()
  };

  // Snapshot alerts via list_alerts and client-side filter on created/detected time
  const list = await listAlerts({ cwd: CWD, first: 100 });
  const edges = list?.edges ?? [];
  const allAlerts = edges.map((e) => e.node).filter(Boolean);
  const alerts = allAlerts.filter((a) => {
    const ts = a.detected_at || a.detectedAt || a.created_at || a.createdAt;
    if (!ts) return false;
    const t = new Date(ts).getTime();
    return t >= startMs && t <= endMs;
  });

  const snapshot = { window, alerts };
  writeJson(path.join(outDir, 'alerts.raw.json'), snapshot);

  if (mode === 'collect') {
    process.stdout.write(`Collected alerts snapshot to ${path.relative(CWD, outDir)}/alerts.raw.json\n`);
    return;
  }

  // The remaining logic (IOCs, enrichment, AI guidance) is kept for non-collect mode and may be phased out
  // as the reasoning agent takes over more of the hunt design.

  // Collect IOCs from top alerts
  const iocSet = new Set();
  const sampled = alerts.slice(0, 15);

  for (const a of sampled) {
    const id = a.id;
    const detail = await getAlert({ cwd: CWD, alertId: id });
    let notes = null;
    if (detail?.note_exists || detail?.noteExists) {
      notes = await getAlertNotes({ cwd: CWD, alertId: id });
    }
    const text = [a.name, a.description, JSON.stringify(detail), notes ? JSON.stringify(notes) : ''].filter(Boolean).join('\n');
    const iocs = extractIOCs(text);
    for (const i of iocs) iocSet.add(`${i.type}:${i.indicator}`);
  }

  const iocs = Array.from(iocSet).slice(0, 50).map((s) => {
    const [type, ...rest] = s.split(':');
    return { type, indicator: rest.join(':') };
  });

  const enriched = iocs.length ? await bulkEnrich({ cwd: CWD, indicators: iocs.map((x) => x.indicator) }) : { count: 0, results: [] };
  writeJson(path.join(outDir, 'iocs.json'), { iocs, enriched });

  // Ask Purple AI to perform the hunt itself over the last 7 days and report evidence
  const huntPrompt = [
    `You are a threat hunter working inside SentinelOne Purple.`,
    `Time window (UTC): ${window.start_time} → ${window.end_time}.`,
    `Alerts searched in this window: ${alerts.length} (sampled ${sampled.length} for IOC extraction).`,
    '',
    `Here is a condensed IOC list extracted from these alerts (type:indicator):`,
    iocs.length ? iocs.map((x) => `- ${x.type}:${x.indicator}`).join('\n') : '- <none>',
    '',
    `Task: Using your own access to the environment and PowerQuery under the hood, hunt for any evidence related to these IOCs in this time window.`,
    `You should run whatever queries you need yourself; DO NOT return queries for someone else to run. Instead, return a human-readable markdown report summarizing whether any of these IOCs appear in the environment.`,
    '',
    `Your markdown response MUST follow this structure:`,
    `# Summary`,
    `- Overall assessment (e.g., "no sightings", "limited sightings", "strong evidence of compromise")`,
    `- Notable hosts / users / time ranges (if any)`,
    '',
    `# Findings by IOC`,
    `For each IOC (even if not seen), list:`,
    `- IOC: <type>:<indicator>`,
    `- Sightings: none | brief description of where/when`,
    `- Confidence: low/medium/high`,
    '',
    `# Gaps / Limitations`,
    `- Any visibility gaps or errors you encountered while hunting`,
    '',
    `If you cannot access the necessary data or queries fail, say so explicitly under Gaps / Limitations.`
  ].join('\n');

  const ai = await purpleAi({ cwd: CWD, query: huntPrompt });
  writeJson(path.join(outDir, 'purple_ai.json'), ai);

  let md = '';
  md += `Threat Hunter — weekly — ${ymd} PT\n`;
  md += `Alerts searched (7d): ${alerts.length} (sampled ${sampled.length})\n`;
  md += `Extracted IOCs: ${iocs.length}\n\n`;
  md += `Purple AI hunt report (direct hunt over environment, no local PowerQuery execution):\n`;
  md += (ai.text ? ai.text : JSON.stringify(ai, null, 2)) + '\n\n';
  md += `Artifacts: ${path.relative(CWD, outDir)}/\n`;

  writeText(path.join(outDir, 'report.md'), md);
  process.stdout.write(md);
}

main().catch((err) => {
  process.stderr.write(String(err?.stack || err) + '\n');
  process.stdout.write(`Threat Hunter: ERROR\n${String(err?.message || err)}\n`);
  process.exitCode = 1;
});
