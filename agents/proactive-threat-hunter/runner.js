#!/usr/bin/env node
import path from 'node:path';
import fs from 'node:fs';

import { ensureDir, writeJson, writeText } from '../../lib/fs.js';
import { bulkEnrich } from '../../lib/ti.js';

const CWD = process.env.SECURITY_LAB_CWD || process.cwd();
const TZ = 'America/Los_Angeles';

function ymdNow() {
  const d = new Date();
  const iso = d.toLocaleString('sv-SE', { timeZone: TZ });
  return iso.split(' ')[0].replaceAll('-', '');
}

async function main() {
  const ymd = ymdNow();
  const outDir = path.join(CWD, 'artifacts', 'cron', 'proactive-hunter', ymd);
  ensureDir(outDir);

  // Source intel from TI Analyst feed (ti_iocs.json)
  const tiRoot = path.join(CWD, 'artifacts', 'cron', 'ti-digest');
  const tiDirs = fs.existsSync(tiRoot) ? fs.readdirSync(tiRoot).filter((d) => /^\d{8}$/.test(d)).sort().reverse() : [];
  const tiDir = tiDirs[0] ? path.join(tiRoot, tiDirs[0]) : null;
  const tiPath = tiDir ? path.join(tiDir, 'ti_iocs.json') : null;

  let ti = { iocs: [] };
  if (tiPath && fs.existsSync(tiPath)) {
    try {
      ti = JSON.parse(fs.readFileSync(tiPath, 'utf8'));
    } catch {
      ti = { iocs: [] };
    }
  }

  const allIocs = Array.isArray(ti?.iocs) ? ti.iocs : [];

  // Deterministic selection: KEV CVEs first, then other CVEs, then domains/IPs.
  const kevCves = allIocs.filter((x) => x?.type === 'cve' && Array.isArray(x?.sources) && x.sources.includes('kev'));
  const otherCves = allIocs.filter((x) => x?.type === 'cve' && !(Array.isArray(x?.sources) && x.sources.includes('kev')));
  const infra = allIocs.filter((x) => ['domain', 'ip', 'url', 'hash'].includes(String(x?.type || '').toLowerCase()));

  const selected = [...kevCves, ...otherCves, ...infra]
    .map((x) => ({ indicator: x.indicator, type: x.type || 'auto', context: x.context ?? x.threatContext ?? null, sources: x.sources ?? null }))
    .filter((x) => x.indicator)
    .slice(0, 15);

  const indicators = selected.map((x) => x.indicator);
  const enriched = indicators.length ? await bulkEnrich({ cwd: CWD, indicators, type: 'auto' }) : { count: 0, results: [] };

  // Minimal collector output for reasoning agent: TI feed context + selected IOCs + optional enrichment.
  writeJson(path.join(outDir, 'ti_iocs.selected.json'), {
    tiFeedPath: tiPath ? path.relative(CWD, tiPath) : null,
    tiFeedCount: allIocs.length,
    selected,
    enriched
  });

  let md = '';
  md += `Proactive Threat Hunter collector — ${ymd} PT\n\n`;
  md += `TI feed: ${tiPath ? path.relative(CWD, tiPath) : 'none'}\n`;
  md += `Selected IOCs for hunts: ${selected.length}\n`;
  if (selected.length) {
    selected.forEach((x, idx) => {
      md += `- IOC${idx + 1}: ${x.type || 'auto'}:${x.indicator}\n`;
    });
  } else {
    md += `- No IOCs selected (empty ti_iocs.json or parse failure).\n`;
  }
  md += `\nArtifacts: ${path.relative(CWD, outDir)}/ (ti_iocs.selected.json, report.md)\n`;

  writeText(path.join(outDir, 'report.md'), md);
  process.stdout.write(md);
}

main().catch((err) => {
  process.stderr.write(String(err?.stack || err) + '\n');
  process.stdout.write(`Proactive Threat Hunter: ERROR\n${String(err?.message || err)}\n`);
  process.exitCode = 1;
});
