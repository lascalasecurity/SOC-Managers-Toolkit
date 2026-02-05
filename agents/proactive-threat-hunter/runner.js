#!/usr/bin/env node
import path from 'node:path';

import { ensureDir, writeJson, writeText } from '../../lib/fs.js';
import { purpleAi } from '../../lib/purple.js';
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

  // v0: until we ingest real feeds, use a small seed list that rotates later.
  const seedIocs = ['CVE-2021-44228', 'CVE-2023-34362', 'example.com'];
  const enriched = await bulkEnrich({ cwd: CWD, indicators: seedIocs, type: 'auto' });
  writeJson(path.join(outDir, 'ti.json'), { seedIocs, enriched });

  const ai = await purpleAi({ cwd: CWD, query: `Using these indicators (CVE/domain) as starting points: ${seedIocs.join(', ')}. Propose 3 PowerQueries to hunt for related exploitation/behavior in the last 7 days. Provide the PowerQueries.` });
  writeJson(path.join(outDir, 'purple_ai.json'), ai);

  let md = '';
  md += `Proactive Threat Hunter — weekly — ${ymd} PT\n\n`;
  md += `Seed intel (v0): ${seedIocs.join(', ')}\n`;
  md += `Purple AI proposed hunts:\n`;
  md += (ai.text ? ai.text : JSON.stringify(ai, null, 2)) + '\n\n';
  md += `Artifacts: ${path.relative(CWD, outDir)}/\n`;

  writeText(path.join(outDir, 'report.md'), md);
  process.stdout.write(md);
}

main().catch((err) => {
  process.stderr.write(String(err?.stack || err) + '\n');
  process.stdout.write(`Proactive Threat Hunter: ERROR\n${String(err?.message || err)}\n`);
  process.exitCode = 1;
});
