#!/usr/bin/env node
import path from 'node:path';

import { mcporterCall } from '../../lib/mcporter.js';
import { ensureDir, writeJson, writeText, readJsonIfExists } from '../../lib/fs.js';
import { summarizeVuln, diffSnapshots } from '../../lib/diff.js';

const CWD = process.env.SECURITY_LAB_CWD || process.cwd();
const TZ = 'America/Los_Angeles';

function stampNow() {
  const d = new Date();
  const iso = d.toLocaleString('sv-SE', { timeZone: TZ });
  const [date, time] = iso.split(' ');
  const [hh, mm] = time.split(':');
  return { ymd: date.replaceAll('-', ''), hhmm: `${hh}${mm}`, stamp: `${date.replaceAll('-', '')}` };
}

function rankSeverity(sev) {
  const m = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0, UNKNOWN: -1 };
  return m[String(sev || 'UNKNOWN').toUpperCase()] ?? -1;
}

function priorityScore(v) {
  // v is summarized vuln
  let s = 0;
  s += (rankSeverity(v.severity) + 1) * 20;
  if (v.kevAvailable) s += 25;
  if (v.exploitedInTheWild) s += 20;
  if (typeof v.epss === 'number') s += Math.round(Math.min(1, v.epss) * 20);
  if (v.fixAvailable) s += 10;
  return Math.max(0, Math.min(100, s));
}

async function main() {
  const mode = process.argv.includes('--mode') ? process.argv[process.argv.indexOf('--mode') + 1] : 'collect';
  const { stamp } = stampNow();
  const outDir = path.join(CWD, 'artifacts', 'cron', 'vuln-manager', stamp);
  const stateDir = path.join(CWD, 'artifacts', 'cron', 'vuln-manager');
  ensureDir(outDir);

  function mkFilters(arr) {
    // purple-mcp expects `filters` to be a STRING containing JSON (array of filters).
    return JSON.stringify(arr);
  }

  async function searchAll({ filtersArr, first = 100, maxPages = 10 }) {
    const edges = [];
    let after = null;
    let pageInfo = null;
    let last = null;
    for (let page = 0; page < maxPages; page++) {
      const res = await mcporterCall({
        cwd: CWD,
        tool: 'purple-mcp.search_vulnerabilities',
        args: {
          filters: mkFilters(filtersArr),
          first,
          after
        },
        output: 'json',
        timeoutMs: 120000
      });

      let j;
      try {
        j = JSON.parse(res.stdout);
      } catch {
        const head = String(res.stdout || '').slice(0, 200);
        throw new Error(`purple-mcp.search_vulnerabilities returned non-JSON output (first 200 chars): ${head}`);
      }

      last = j;
      const newEdges = j?.edges ?? [];
      edges.push(...newEdges);
      pageInfo = j?.page_info ?? null;

      if (!pageInfo?.has_next_page) break;
      after = pageInfo?.end_cursor;
      if (!after) break;
      if (newEdges.length === 0) break;
    }

    return {
      edges,
      page_info: pageInfo,
      total_count: Number(last?.total_count ?? last?.totalCount ?? edges.length),
      paged: true
    };
  }

  async function getCount({ filtersArr }) {
    const res = await mcporterCall({
      cwd: CWD,
      tool: 'purple-mcp.search_vulnerabilities',
      args: {
        filters: mkFilters(filtersArr),
        first: 1,
        after: null
      },
      output: 'json',
      timeoutMs: 120000
    });
    const j = JSON.parse(res.stdout);
    return Number(j?.total_count ?? j?.totalCount ?? (j?.edges?.length ?? 0));
  }

  // Collector behavior: capture posture counts + a bounded working set for prioritization.
  const baseStatus = [{ fieldId: 'status', filterType: 'string_equals', value: 'NEW' }];
  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  const countsBySeverity = {};
  for (const sev of severities) {
    countsBySeverity[sev] = await getCount({
      filtersArr: [...baseStatus, { fieldId: 'severity', filterType: 'string_equals', value: sev }]
    });
  }

  const topSetFilters = [
    ...baseStatus,
    { fieldId: 'severity', filterType: 'string_in', values: ['CRITICAL', 'HIGH'] }
  ];

  const topSet = await searchAll({ filtersArr: topSetFilters, first: 100, maxPages: 10 }); // max 1000 rows

  const listJson = {
    generatedAt: new Date().toISOString(),
    query: {
      status: 'NEW',
      severitiesCounted: severities,
      topSet: { severities: ['CRITICAL', 'HIGH'], maxRows: topSet.edges.length }
    },
    countsBySeverity,
    topSet
  };

  writeJson(path.join(outDir, 'vulnerabilities.raw.json'), listJson);

  if (mode === 'collect') {
    process.stdout.write(`Collected vulnerability posture to ${path.relative(CWD, outDir)}/vulnerabilities.raw.json (counts + topSet sample)\n`);
    return;
  }

  const edges = listJson?.topSet?.edges ?? [];
  const vulns = edges.map((e) => e.node).filter(Boolean);
  const summarized = vulns.map(summarizeVuln);

  const prev = readJsonIfExists(path.join(stateDir, 'last.json'));
  const prevList = prev?.summarized ?? null;

  const diff = prevList ? diffSnapshots(prevList, summarized) : { added: [], removed: [], changed: [] };

  // Enrich top CVEs (KEV) for top 10 candidates
  const scored = summarized.map((v) => ({ ...v, priority: priorityScore(v) }));
  scored.sort((a, b) => b.priority - a.priority);

  const top10 = scored.slice(0, 10);

  const kev = {};
  for (const v of top10) {
    if (!v.cve) continue;
    try {
      const r = await mcporterCall({
        cwd: CWD,
        tool: 'ti-aggregator.cve_report',
        args: { cve: v.cve },
        output: 'json',
        timeoutMs: 120000
      });
      kev[v.cve] = JSON.parse(r.stdout);
    } catch (e) {
      kev[v.cve] = { error: String(e?.message || e) };
    }
  }

  writeJson(path.join(outDir, 'top10.json'), { top10, kev });

  // Persist state
  writeJson(path.join(stateDir, 'last.json'), {
    generatedAt: new Date().toISOString(),
    summarized,
    diff
  });

  // Report
  let md = '';
  md += `Vulnerability Manager — ${stamp} PT\n`;
  md += `Fetched: ${summarized.length} vulnerabilities (showing top 10 prioritized)\n\n`;

  if (prevList) {
    md += `Changes since last run:\n`;
    md += `- New: ${diff.added.length}\n`;
    md += `- Removed: ${diff.removed.length}\n`;
    md += `- Changed: ${diff.changed.length}\n\n`;
  } else {
    md += `No previous snapshot found (first run baseline).\n\n`;
  }

  md += `Top 10 prioritized:\n`;
  for (const v of top10) {
    const kevHit = v.cve ? kev[v.cve]?.knownExploited : undefined;
    md += `- [${v.severity}] ${v.name} — ${v.asset ?? 'unknown asset'} — priority ${v.priority}/100\n`;
    if (v.cve) md += `  CVE: ${v.cve} (KEV: ${kevHit === true ? 'YES' : kevHit === false ? 'no' : 'unknown'})\n`;
    if (v.fixAvailable) md += `  Fix: ${v.softwareFixVersion ?? 'available'}\n`;
  }

  md += `\nArtifacts: ${path.relative(CWD, outDir)}/ (vulnerabilities.raw.json, top10.json, report.md)\n`;

  writeText(path.join(outDir, 'report.md'), md);
  process.stdout.write(md);
}

main().catch((err) => {
  process.stderr.write(String(err?.stack || err) + '\n');
  process.stdout.write(`Vulnerability Manager: ERROR\n${String(err?.message || err)}\n`);
  process.exitCode = 1;
});
