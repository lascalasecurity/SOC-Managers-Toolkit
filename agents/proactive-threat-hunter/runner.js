#!/usr/bin/env node
import path from 'node:path';

import { ensureDir, writeJson, writeText } from '../../lib/fs.js';
import { purpleAi, getTimestampRange, runPowerQuery } from '../../lib/purple.js';
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

  // Extract PowerQueries from Purple AI text (very simple heuristic: code blocks or lines starting with SELECT)
  const text = ai.text ?? (Array.isArray(ai.content) && ai.content[0]?.text) ?? '';
  const queries = [];
  if (text) {
    const codeBlockRegex = /```sql[\s\S]*?```/gi;
    let m;
    while ((m = codeBlockRegex.exec(text)) && queries.length < 5) {
      const q = m[0].replace(/```sql|```/gi, '').trim();
      if (q) queries.push(q);
    }
    if (!queries.length) {
      // Fallback: grab lines that look like SQL SELECTs
      for (const line of text.split('\n')) {
        if (/^\s*select\s+/i.test(line)) queries.push(line.trim());
        if (queries.length >= 5) break;
      }
    }
  }

  const range = await getTimestampRange({ cwd: CWD, hours: 24 * 7 });
  const pqResults = [];
  for (let i = 0; i < queries.length; i++) {
    const q = queries[i];
    try {
      const res = await runPowerQuery({ cwd: CWD, query: q, startMs: range.start_timestamp, endMs: range.end_timestamp });
      pqResults.push({ index: i, query: q, resultSummary: res?.summary ?? null, result: res });
      writeJson(path.join(outDir, `powerquery_${i}.json`), res);
    } catch (e) {
      pqResults.push({ index: i, query: q, error: String(e?.message || e) });
    }
  }
  writeJson(path.join(outDir, 'powerqueries.json'), { queries, pqResults });

  let md = '';
  md += `Proactive Threat Hunter — weekly — ${ymd} PT\n\n`;
  md += `Seed intel (v0): ${seedIocs.join(', ')}\n`;
  md += `Purple AI proposed hunts (executed ${pqResults.length} PowerQueries over last 7 days):\n`;
  if (queries.length) {
    queries.forEach((q, idx) => {
      md += `- PQ${idx + 1}: ${q.slice(0, 120).replace(/\s+/g, ' ')}${q.length > 120 ? ' ...' : ''}\n`;
    });
  } else {
    md += `- No executable PowerQueries could be parsed from Purple AI response.\n`;
  }
  md += `\nArtifacts: ${path.relative(CWD, outDir)}/ (ti.json, purple_ai.json, powerqueries.json, powerquery_*.json, report.md)\n`;

  writeText(path.join(outDir, 'report.md'), md);
  process.stdout.write(md);
}

main().catch((err) => {
  process.stderr.write(String(err?.stack || err) + '\n');
  process.stdout.write(`Proactive Threat Hunter: ERROR\n${String(err?.message || err)}\n`);
  process.exitCode = 1;
});
