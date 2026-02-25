import fs from 'node:fs/promises';
import path from 'node:path';

import { ensureDir, writeJson, writeText } from '../../lib/fs.js';
import { getTimestampRange, purpleAi, runPowerQuery } from '../../lib/purple.js';

const CWD = process.env.SECURITY_LAB_CWD || process.cwd();
const TZ = 'America/Los_Angeles';

function ymdNow() {
  const d = new Date();
  const iso = d.toLocaleString('sv-SE', { timeZone: TZ });
  return iso.split(' ')[0].replaceAll('-', '');
}

function uniq(arr) {
  return [...new Set(arr.filter(Boolean))];
}

function parseSelected(selected) {
  const cves = [];
  const domains = [];
  const ips = [];
  const urls = [];
  const hashes = [];

  for (const x of selected || []) {
    const type = String(x?.type || '').toLowerCase();
    const ind = String(x?.indicator || '').trim();
    if (!ind) continue;
    if (type === 'cve') cves.push(ind);
    else if (type === 'domain') domains.push(ind);
    else if (type === 'ip') ips.push(ind);
    else if (type === 'url') urls.push(ind);
    else if (type === 'hash') hashes.push(ind);
    else {
      // fallback heuristic
      if (/^CVE-\d{4}-\d+$/i.test(ind)) cves.push(ind);
      else if (/^https?:\/\//i.test(ind)) urls.push(ind);
      else if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ind)) ips.push(ind);
      else if (/^[a-f0-9]{64}$/i.test(ind)) hashes.push(ind);
      else domains.push(ind);
    }
  }

  return {
    cves: uniq(cves),
    domains: uniq(domains),
    ips: uniq(ips),
    urls: uniq(urls),
    hashes: uniq(hashes)
  };
}

async function main() {
  const ymd = ymdNow();
  const outDir = path.join(CWD, 'artifacts', 'cron', 'proactive-hunter', ymd);
  await ensureDir(outDir);

  const selectedPath = path.join(outDir, 'ti_iocs.selected.json');
  const selectedRaw = JSON.parse(await fs.readFile(selectedPath, 'utf8'));
  const selected = selectedRaw?.selected || [];
  const parsed = parseSelected(selected);

  // Default to last 24 hours (daily proactive hunts).
  const range = await getTimestampRange({ cwd: CWD, hours: 24 });
  const startIso = range?.startIso || new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const endIso = range?.endIso || new Date().toISOString();

  const hunts = [];
  const pqRuns = [];

  function logStep(msg) {
    process.stdout.write(`[proactive-hunter] ${msg}\n`);
  }

  logStep(`Starting hunts: window=${startIso}..${endIso} domains=${parsed.domains.length} ips=${parsed.ips.length} hashes=${parsed.hashes.length}`);

  async function genAndRun({ id, description, scopeText, aiHint, maxRows = 200 }) {
    logStep(`${id}: generating PowerQuery via purple_ai...`);
    // Use Purple AI to generate a PowerQuery that is compatible with the current Purple schema.
    const aiPrompt = [
      `You are generating a SentinelOne Purple PowerQuery for a TI-driven threat hunt in a mixed Windows + Linux environment.`,
      `Return ONLY the PowerQuery text (no backticks, no explanation).`,
      `Time window (UTC): ${startIso} -> ${endIso}.`,
      `Limit results to <= ${maxRows} rows.`,
      `Output columns (when available): timestamp, hostname/asset, username, process image/path, command line, parent process, remote_ip/remote_domain, remote_port, local_ip, url, dns_query.`,
      '',
      `Hunt: ${description}`,
      `Scope/indicators: ${scopeText}`,
      aiHint ? `Notes: ${aiHint}` : ''
    ].filter(Boolean).join('\n');

    const ai = await purpleAi({ cwd: CWD, query: aiPrompt });
    let pq = (ai?.text || '').toString().trim();
    pq = pq.replace(/^```[a-zA-Z]*\n/, '').replace(/\n```\s*$/, '').trim();

    const bad = (!pq) || pq.toLowerCase().includes('purple ai encountered an error') || !(pq.startsWith('|') || pq.toLowerCase().includes('filter('));

    if (bad) {
      logStep(`${id}: purple_ai output invalid; skipping powerquery.`);
    } else {
      logStep(`${id}: executing powerquery (timeout up to 300s)...`);
    }

    let run = { status: 'error', error: 'empty/invalid query', rows: [] };
    if (!bad) {
      try {
        run = await runPowerQuery({ cwd: CWD, query: pq, startIso, endIso });
      } catch (e) {
        run = { status: 'error', error: String(e?.message || e) };
      }
    } else {
      run = { status: 'error', error: 'purple_ai did not return runnable PowerQuery text', aiRaw: ai };
    }

    const rows = Array.isArray(run?.rows) ? run.rows : (Array.isArray(run?.data) ? run.data : []);
    const matchCount = typeof run?.matchCount === 'number' ? run.matchCount : (Array.isArray(rows) ? rows.length : null);

    pqRuns.push({ id, start: startIso, end: endIso, query: pq, status: run?.error ? 'error' : 'ok', matchCount: matchCount ?? null, sampleRows: (rows || []).slice(0, 10), error: run?.error || null });

    const signal = run?.error
      ? 'inconclusive'
      : (matchCount && matchCount > 0 ? 'suspicious' : 'no_evidence');

    const status = run?.error ? 'ERROR' : (matchCount === 0 ? 'NO_HITS' : (matchCount != null ? `HITS:${matchCount}` : 'UNKNOWN'));
    logStep(`${id}: done → ${status}`);

    hunts.push({
      id,
      description,
      timeWindow: { start: startIso, end: endIso },
      queries: pq ? [pq] : [],
      result: {
        status: run?.error ? 'error' : 'completed',
        signal,
        evidence: run?.error ? String(run.error) : (matchCount > 0 ? `Matches: ${matchCount}` : 'No matches in sampled window'),
        notes: run?.error ? 'purple_ai query generation failed or powerquery execution failed; see powerqueries.json for details.' : null
      }
    });
  }

  // Only run hunts for non-CVE indicators (CVEs are handled via exposure/patch workflows, not telemetry hunts here).
  if (parsed.domains.length) {
    await genAndRun({
      id: 'hunt_dns_domain_sightings',
      description: 'DNS/proxy sightings for TI domains (possible infostealer infra)',
      scopeText: parsed.domains.slice(0, 15).map(d => d).join(', '),
      aiHint: 'Search DNS queries, HTTP host headers, TLS SNI, and proxy logs if available.'
    });
  }

  if (parsed.ips.length) {
    await genAndRun({
      id: 'hunt_outbound_ip_connections',
      description: 'Outbound network connections to TI IPs',
      scopeText: parsed.ips.slice(0, 15).join(', '),
      aiHint: 'Prefer network connection telemetry tables; include process context.'
    });
  }

  if (parsed.hashes.length) {
    await genAndRun({
      id: 'hunt_filehash_sightings',
      description: 'File/process hash sightings for TI hashes',
      scopeText: parsed.hashes.slice(0, 10).join(', '),
      aiHint: 'Search file hash fields for sha256/sha1/md5; include execution context.'
    });
  }

  // Write artifacts.
  const huntsDoc = {
    tiFeedPath: selectedRaw?.tiFeedPath || null,
    tiFeedCount: selectedRaw?.tiFeedCount || null,
    selectedIocs: selected.map(x => x?.indicator).filter(Boolean),
    selectedParsed: parsed,
    iocGroups: [
      {
        name: 'TI infra sightings (domains / IPs / hashes)',
        iocs: [...parsed.domains, ...parsed.ips, ...parsed.hashes],
        hypotheses: [
          'If endpoints/users interacted with this infra recently, we should see DNS/proxy/connection telemetry referencing these domains/IPs.',
          'If the hashes represent executed malware, we should see file hash sightings or process execution context.'
        ],
        hunts
      }
    ],
    overallAssessment: {
      summary: 'See per-hunt results. This run is scoped to a 24-hour window and focuses on infra IOCs selected from TI Digest.',
      signal: hunts.some(h => h.result?.signal === 'suspicious') ? 'suspicious' : 'no_evidence',
      confidence: hunts.some(h => h.result?.status === 'error') ? 'low' : 'medium',
      constraints: hunts.filter(h => h.result?.status === 'error').map(h => `${h.id}: ${h.result?.evidence}`)
    }
  };

  logStep('Writing artifacts...');
  await writeJson(path.join(outDir, 'hunts.json'), huntsDoc);
  await writeJson(path.join(outDir, 'powerqueries.json'), pqRuns);

  const results = {
    tiFeedPath: huntsDoc.tiFeedPath,
    selectedCount: huntsDoc.selectedIocs.length,
    huntCount: hunts.length,
    completed: hunts.filter(h => h.result?.status === 'completed').length,
    errors: hunts.filter(h => h.result?.status === 'error').length,
    suspiciousSignals: hunts.filter(h => h.result?.signal === 'suspicious').length,
    positiveHits: hunts.filter(h => h.result?.signal === 'positive_hit').length,
    overallSignal: huntsDoc.overallAssessment.signal,
    overallConfidence: huntsDoc.overallAssessment.confidence
  };
  await writeJson(path.join(outDir, 'results.json'), results);

  // Append execution summary to collector report.md
  const reportPath = path.join(outDir, 'report.md');
  let report = '';
  try { report = await fs.readFile(reportPath, 'utf8'); } catch { report = ''; }

  report += `\n---\n## Hunt execution summary\n\n`;
  report += `- Time window (UTC): ${startIso} → ${endIso}\n`;
  report += `- Hunts executed: ${hunts.length} total (${results.completed} completed, ${results.errors} errors)\n`;
  report += `- Signals: ${results.positiveHits} positive hits, ${results.suspiciousSignals} suspicious\n`;
  report += `- Artifacts:\n`;
  report += `  - Hunts definition/results: artifacts/cron/proactive-hunter/${ymd}/hunts.json\n`;
  report += `  - PowerQuery runs: artifacts/cron/proactive-hunter/${ymd}/powerqueries.json\n`;
  report += `  - Summary: artifacts/cron/proactive-hunter/${ymd}/results.json\n`;

  await writeText(reportPath, report);

  process.stdout.write(`Proactive Threat Hunter — ${ymd} — hunts:${hunts.length} suspicious:${results.suspiciousSignals} errors:${results.errors}\n`);
  process.stdout.write(`Artifacts: artifacts/cron/proactive-hunter/${ymd}/\n`);
}

main().catch((err) => {
  process.stderr.write(String(err?.stack || err) + '\n');
  process.exitCode = 1;
});
