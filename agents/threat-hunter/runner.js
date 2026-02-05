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

  // Snapshot alerts via list_alerts and client-side filter on created/detected time
  const list = await listAlerts({ cwd: CWD, first: 100 });
  const edges = list?.edges ?? [];
  const allAlerts = edges.map((e) => e.node).filter(Boolean);
  const alerts = allAlerts.filter((a) => {
    const ts = a.detected_at || a.detectedAt || a.created_at || a.createdAt;
    if (!ts) return false;
    const t = new Date(ts).getTime();
    return t >= range.start_timestamp && t <= range.end_timestamp;
  });

  const snapshot = { window: range, alerts };
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

  // Ask Purple AI for hunt guidance (v0: one prompt)
  const ai = await purpleAi({ cwd: CWD, query: `We saw ${iocs.length} IOCs from alerts this week. Suggest 3-5 PowerQuery hunts to check for follow-on compromise (last 7 days). Focus on ransomware/lateral movement and credential access.` });
  writeJson(path.join(outDir, 'purple_ai.json'), ai);

  let md = '';
  md += `Threat Hunter — weekly — ${ymd} PT\n`;
  md += `Alerts searched (7d): ${alerts.length} (sampled ${sampled.length})\n`;
  md += `Extracted IOCs: ${iocs.length}\n\n`;
  md += `Next hunts (from Purple AI):\n`;
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
