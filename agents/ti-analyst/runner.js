#!/usr/bin/env node
import path from 'node:path';
import fs from 'node:fs';

import { ensureDir, writeJson, writeText, readJsonIfExists } from '../../lib/fs.js';
import { bulkEnrich } from '../../lib/ti.js';

const CWD = process.env.SECURITY_LAB_CWD || process.cwd();
const TZ = 'America/Los_Angeles';

function ymdNow() {
  const d = new Date();
  const iso = d.toLocaleString('sv-SE', { timeZone: TZ });
  return iso.split(' ')[0].replaceAll('-', '');
}

function parseArgs(argv) {
  const out = { mode: 'collect', input: null, enrich: false, limit: 100 };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--mode') out.mode = argv[++i] || out.mode;
    else if (a === '--input') out.input = argv[++i] || null;
    else if (a === '--enrich') out.enrich = true;
    else if (a === '--limit') out.limit = Number(argv[++i] || out.limit);
  }
  return out;
}

function normalizeIoc(x) {
  if (!x) return null;

  // Allow either a bare string indicator or an object.
  if (typeof x === 'string') {
    return { indicator: x.trim(), type: 'auto' };
  }

  const indicator = String(x.indicator ?? x.value ?? '').trim();
  if (!indicator) return null;
  const type = String(x.type ?? 'auto').trim() || 'auto';

  return {
    indicator,
    type,
    // optional metadata passthrough
    sources: x.sources,
    context: x.context,
    tags: x.tags,
    confidence: x.confidence,
    relevance: x.relevance,
    firstSeen: x.firstSeen,
    ttlDays: x.ttlDays
  };
}

function dedupe(iocs) {
  const seen = new Set();
  const out = [];
  for (const i of iocs) {
    const k = `${String(i.type || 'auto').toLowerCase()}:${i.indicator}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(i);
  }
  return out;
}

async function main() {
  const { mode, input, enrich, limit } = parseArgs(process.argv);
  if (mode !== 'collect') {
    process.stdout.write(`TI Analyst runner is a helper/collector. Use --mode collect. (got: ${mode})\n`);
    process.exitCode = 2;
    return;
  }

  const ymd = ymdNow();
  const outDir = path.join(CWD, 'artifacts', 'cron', 'ti-digest', ymd);
  ensureDir(outDir);

  // Input format: { iocs: [ {indicator, type?, ...} ] } or just [ ... ]
  // Default input file (optional): config/ti-iocs.seed.json
  const defaultInputPath = path.join(CWD, 'config', 'ti-iocs.seed.json');
  const inPath = input ? path.resolve(CWD, input) : defaultInputPath;

  let raw = null;
  if (fs.existsSync(inPath)) {
    raw = readJsonIfExists(inPath);
  }

  const rawList = Array.isArray(raw) ? raw : Array.isArray(raw?.iocs) ? raw.iocs : [];

  const normalized = dedupe(rawList.map(normalizeIoc).filter(Boolean)).slice(0, Math.max(0, limit));

  // Schema v0: deterministic list + optional enrichment blob.
  const tiIocs = normalized.map((i) => ({
    indicator: i.indicator,
    type: i.type || 'auto',
    context: i.context ?? null,
    tags: Array.isArray(i.tags) ? i.tags : null,
    confidence: i.confidence ?? 'unknown',
    relevance: i.relevance ?? 'unknown',
    sources: Array.isArray(i.sources) ? i.sources : null,
    firstSeen: i.firstSeen ?? null,
    ttlDays: i.ttlDays ?? null
  }));

  writeJson(path.join(outDir, 'ti_iocs.json'), {
    generatedAt: new Date().toISOString(),
    schema: 'security-lab:ti-iocs:v0',
    input: {
      path: fs.existsSync(inPath) ? path.relative(CWD, inPath) : null,
      count: rawList.length
    },
    count: tiIocs.length,
    iocs: tiIocs
  });

  if (enrich && tiIocs.length) {
    // Optional: bulk enrich for downstream agents (still deterministic; no judgment).
    const indicators = tiIocs.map((x) => x.indicator);
    const enrichment = await bulkEnrich({ cwd: CWD, indicators, type: 'auto' });
    writeJson(path.join(outDir, 'enrichment.json'), enrichment);
  }

  let md = '';
  md += `TI Analyst (collector) — ${ymd} PT\n`;
  md += `Wrote: ${path.relative(CWD, outDir)}/ti_iocs.json\n`;
  md += `IOCs: ${tiIocs.length}\n`;
  md += `Input: ${fs.existsSync(inPath) ? path.relative(CWD, inPath) : '(none; created empty set)'}\n`;
  md += `Enrichment: ${enrich ? 'enabled' : 'disabled'}\n`;

  writeText(path.join(outDir, 'collector.log.txt'), md);
  process.stdout.write(md);
}

main().catch((err) => {
  process.stderr.write(String(err?.stack || err) + '\n');
  process.stdout.write(`TI Analyst: ERROR\n${String(err?.message || err)}\n`);
  process.exitCode = 1;
});
