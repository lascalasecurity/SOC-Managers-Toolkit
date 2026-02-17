#!/usr/bin/env node
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

import express from 'express';
import chokidar from 'chokidar';
import MarkdownIt from 'markdown-it';

const ROOT = process.env.SECURITY_LAB_CWD || path.resolve(process.cwd());
const ARTIFACTS_ROOT = path.join(ROOT, 'artifacts', 'cron');
const PUBLIC_DIR = path.join(ROOT, 'dashboard', 'public');

const HOST = process.env.DASHBOARD_HOST || '127.0.0.1';
const PORT = Number(process.env.DASHBOARD_PORT || 18888);

const md = new MarkdownIt({
  html: false,
  linkify: true,
  typographer: true
});

function safeJoin(root, rel) {
  const p = path.resolve(root, rel);
  if (!p.startsWith(root + path.sep)) throw new Error('path_outside_root');
  return p;
}

async function exists(p) {
  try {
    await fsp.access(p);
    return true;
  } catch {
    return false;
  }
}

function idFromPath(p) {
  return crypto.createHash('sha1').update(p).digest('hex').slice(0, 12);
}

async function listDirs(p) {
  if (!(await exists(p))) return [];
  const entries = await fsp.readdir(p, { withFileTypes: true });
  return entries.filter((e) => e.isDirectory()).map((e) => e.name);
}

async function listFiles(p) {
  if (!(await exists(p))) return [];
  const entries = await fsp.readdir(p, { withFileTypes: true });
  return entries.filter((e) => e.isFile()).map((e) => e.name);
}

async function readJson(p) {
  const raw = await fsp.readFile(p, 'utf8');
  return JSON.parse(raw);
}

async function readText(p) {
  return await fsp.readFile(p, 'utf8');
}

function guessAgentDisplayName(agent) {
  const map = {
    'security-analyst': 'Security Analyst',
    'vuln-manager': 'Vulnerability Manager',
    'ti-digest': 'TI Digest',
    'threat-hunter': 'Threat Hunter',
    'proactive-hunter': 'Proactive Threat Hunter',
    'soc-manager': 'SOC Manager'
  };
  return map[agent] || agent;
}

function guessRunTimestamp(runDirName) {
  // Supports:
  // - YYYYMMDD-HHMM
  // - YYYYMMDD
  // - other → null
  const s = String(runDirName);
  if (/^\d{8}-\d{4}$/.test(s)) return s;
  if (/^\d{8}$/.test(s)) return s;
  return null;
}

function stampToDate(stamp) {
  const ts = guessRunTimestamp(stamp);
  if (!ts) return null;
  const m = ts.match(/^(\d{4})(\d{2})(\d{2})(?:-(\d{2})(\d{2}))?$/);
  if (!m) return null;
  const [, y, mo, d, hh, mi] = m;
  const year = Number(y);
  const month = Number(mo) - 1;
  const day = Number(d);
  const hour = hh ? Number(hh) : 0;
  const min = mi ? Number(mi) : 0;
  return new Date(Date.UTC(year, month, day, hour, min));
}

async function computeWeeklyStats(agent, agentDir, dirs, days = 7) {
  const now = Date.now();
  const horizon = now - days * 24 * 60 * 60 * 1000;
  const recent = dirs.filter((d) => {
    const dt = stampToDate(d);
    return dt && dt.getTime() >= horizon;
  });

  const out = { runs7d: recent.length };

  if (!recent.length) return out;

  if (agent === 'security-analyst') {
    const idSet = new Set();
    for (const r of recent) {
      const dir = path.join(agentDir, r);
      const p = path.join(dir, 'alerts.json');
      try {
        const j = await readJson(p);
        const nodes = (j?.edges || []).map((e) => e?.node).filter(Boolean);
        for (const n of nodes) {
          const ts = n.detected_at || n.detectedAt || n.created_at || n.createdAt;
          const id = n.id;
          if (!id || !ts) continue;
          const t = new Date(ts).getTime();
          if (t >= horizon && t <= now) idSet.add(id);
        }
      } catch {
        // ignore missing/invalid runs
      }
    }
    out.alerts7d = idSet.size;
  }

  if (agent === 'proactive-hunter' || agent === 'threat-hunter') {
    let hunts = 0;
    for (const r of recent) {
      const dir = path.join(agentDir, r);
      const p = path.join(dir, 'hunts.json');
      try {
        const j = await readJson(p);
        if (Array.isArray(j?.hunts)) hunts += j.hunts.length;
        else hunts += 1; // count the run
      } catch {
        hunts += 1; // at least count the run
      }
    }
    out.hunts7d = hunts;
  }

  if (agent === 'soc-manager') {
    let dailyReports = 0;
    let weeklyReports = 0;
    let qaIssues = 0;

    for (const r of recent) {
      const dir = path.join(agentDir, r);
      const files = await listFiles(dir);
      if (files.includes('overview-daily.md')) dailyReports++;
      if (files.includes('overview.md')) {
        weeklyReports++;
        try {
          const txt = await readText(path.join(dir, 'overview.md'));
          const m = txt.match(/Cross-Agent QA[\s\S]*?(?=^## |\n#|$)/m);
          if (m && m[0]) {
            const lines = m[0].split(/\r?\n/);
            for (const line of lines) {
              if (/^\s*-\s+/.test(line)) qaIssues++;
            }
          }
        } catch {
          // ignore
        }
      }
    }

    out.dailyReports7d = dailyReports;
    out.weeklyReports7d = weeklyReports;
    out.qaIssues7d = qaIssues;
  }

  return out;
}

async function getLatestRun(agent) {
  const agentDir = path.join(ARTIFACTS_ROOT, agent);
  let dirs = await listDirs(agentDir);
  if (!dirs.length) return null;

  // Only consider directories that look like run stamps.
  // This prevents stray folders like "test" from showing up as the "latest run".
  dirs = dirs.filter((d) => guessRunTimestamp(d));
  if (!dirs.length) return null;

  // Sort lexicographically descending works for YYYYMMDD(-HHMM) stamps.
  dirs.sort().reverse();
  const latest = dirs[0];
  const full = path.join(agentDir, latest);
  const files = await listFiles(full);

  const { primaryMarkdown, preview } = await tryReadPreviewMarkdown(full, files);
  const summary = await computeDeterministicSummary(agent, full, files);
  const weekly = await computeWeeklyStats(agent, agentDir, dirs);

  return {
    id: idFromPath(path.join(agent, latest)),
    agent,
    agentName: guessAgentDisplayName(agent),
    run: latest,
    ts: guessRunTimestamp(latest),
    path: path.join(agent, latest),
    files,
    primaryMarkdown,
    preview,
    summary,
    weekly
  };
}

function stripMarkdown(s) {
  // very lightweight “good enough” preview: remove code fences + headings + bullets
  return String(s)
    .replace(/```[\s\S]*?```/g, '')
    .replace(/^#{1,6}\s+/gm, '')
    .replace(/^\s*[-*+]\s+/gm, '')
    .replace(/^\s*\d+\.\s+/gm, '')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/\*([^*]+)\*/g, '$1')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

async function tryReadPreviewMarkdown(runDirFull, files) {
  const primary = files.includes('report.md') ? 'report.md' : files.includes('digest.md') ? 'digest.md' : null;
  if (!primary) return { primaryMarkdown: null, preview: null };
  try {
    const text = await readText(path.join(runDirFull, primary));
    const preview = stripMarkdown(text).slice(0, 420);
    return { primaryMarkdown: primary, preview };
  } catch {
    return { primaryMarkdown: primary, preview: null };
  }
}

async function computeDeterministicSummary(agent, runDirFull, files) {
  try {
    if (agent === 'security-analyst' && files.includes('alerts.json')) {
      const j = await readJson(path.join(runDirFull, 'alerts.json'));
      const nodes = (j?.edges || []).map((e) => e?.node).filter(Boolean);
      const bySeverity = {};
      const byStatus = {};
      const now = Date.now();
      const horizon24 = now - 24 * 60 * 60 * 1000;
      let new24h = 0;
      let openHighCrit = 0;

      for (const n of nodes) {
        const sev = String(n.severity || 'UNKNOWN').toUpperCase();
        const st = String(n.status || 'UNKNOWN').toUpperCase();
        bySeverity[sev] = (bySeverity[sev] || 0) + 1;
        byStatus[st] = (byStatus[st] || 0) + 1;

        // Alerts still open and high impact
        if ((sev === 'CRITICAL' || sev === 'HIGH') && st !== 'RESOLVED' && st !== 'CLOSED') {
          openHighCrit++;
        }

        // Alerts detected in the last 24h (trend of incoming alerts)
        const ts = n.detected_at || n.detectedAt || n.created_at || n.createdAt;
        if (ts) {
          const t = new Date(ts).getTime();
          if (!Number.isNaN(t) && t >= horizon24 && t <= now) new24h++;
        }
      }

      const top = nodes
        .slice()
        .sort((a, b) => String(b.detected_at || '').localeCompare(String(a.detected_at || '')))
        .slice(0, 3)
        .map((n) => ({
          id: n.id,
          severity: n.severity,
          status: n.status,
          name: n.name,
          asset: n.asset?.name || null,
          detected_at: n.detected_at || null
        }));

      return {
        kind: 'alerts',
        total: nodes.length,
        bySeverity,
        byStatus,
        top,
        new24h,
        openHighCrit
      };
    }

    if (agent === 'vuln-manager' && files.includes('vulnerabilities.raw.json')) {
      const j = await readJson(path.join(runDirFull, 'vulnerabilities.raw.json'));
      const nodes = (j?.edges || []).map((e) => e?.node).filter(Boolean);
      const bySeverity = {};
      let exploited = 0;
      let kev = 0;
      for (const n of nodes) {
        const sev = String(n.severity || 'UNKNOWN').toUpperCase();
        bySeverity[sev] = (bySeverity[sev] || 0) + 1;
        if (n.exploited_in_the_wild === true || n.exploitedInTheWild === true) exploited++;
        if (n.kev_available === true || n.kevAvailable === true) kev++;
      }
      const top = nodes
        .slice()
        .sort((a, b) => {
          const sa = String(a.severity || '').toUpperCase();
          const sb = String(b.severity || '').toUpperCase();
          const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0, UNKNOWN: -1 };
          return (rank[sb] ?? -1) - (rank[sa] ?? -1);
        })
        .slice(0, 5)
        .map((n) => ({
          id: n.id,
          severity: n.severity,
          name: n.name,
          cve: n.cve || null,
          asset: n.asset?.name || n.asset || null
        }));

      return {
        kind: 'vulns',
        total: nodes.length,
        bySeverity,
        exploitedInTheWild: exploited,
        kevAvailable: kev,
        top
      };
    }

    if (agent === 'ti-digest' && files.includes('ti_iocs.json')) {
      const j = await readJson(path.join(runDirFull, 'ti_iocs.json'));
      const iocs = Array.isArray(j?.iocs) ? j.iocs : [];
      const byType = {};
      let kevCount = 0;
      const kevCves = [];
      for (const i of iocs) {
        const t = String(i.type || 'unknown').toLowerCase();
        byType[t] = (byType[t] || 0) + 1;
        const sources = Array.isArray(i.sources) ? i.sources : [];
        if (sources.includes('kev')) {
          kevCount++;
          if (t === 'cve') kevCves.push(i.indicator);
        }
      }

      return {
        kind: 'ti',
        total: iocs.length,
        byType,
        kevCount,
        topKevCves: kevCves.slice(0, 6)
      };
    }

    // Generic / unknown agent: no deterministic summary yet.
    return null;
  } catch {
    return { kind: 'error', error: 'summary_parse_failed' };
  }
}

async function getSocDaily() {
  const socDir = path.join(ARTIFACTS_ROOT, 'soc-manager');
  const days = await listDirs(socDir);
  if (!days.length) return { ok: false, error: 'no_daily_reports' };
  days.sort().reverse();
  const latestDay = days[0];
  const dayDir = path.join(socDir, latestDay);
  const files = await listFiles(dayDir);

  const dailyName = files.includes('overview-daily.md') ? 'overview-daily.md' : files.includes('overview.md') ? 'overview.md' : null;
  if (!dailyName) return { ok: false, error: 'no_overview_daily' };

  const p = path.join(dayDir, dailyName);
  const text = await readText(p);
  const html = md.render(text);

  return {
    ok: true,
    day: latestDay,
    file: dailyName,
    path: path.join('soc-manager', latestDay, dailyName),
    text,
    html
  };
}

async function getOverview() {
  const agents = await listDirs(ARTIFACTS_ROOT);
  agents.sort();

  const tiles = [];
  for (const a of agents) {
    // Skip background/maintenance agents such as the Janitor; they should not appear as tiles.
    if (a === 'janitor') continue;

    const latest = await getLatestRun(a);
    tiles.push({
      agent: a,
      agentName: guessAgentDisplayName(a),
      latest
    });
  }

  return {
    ok: true,
    artifactsRoot: ARTIFACTS_ROOT,
    agents: tiles
  };
}

// --- SSE ---
const sseClients = new Set();
function sseBroadcast(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try {
      res.write(msg);
    } catch {
      // ignore
    }
  }
}

const watcher = chokidar.watch(ARTIFACTS_ROOT, {
  ignoreInitial: true,
  awaitWriteFinish: { stabilityThreshold: 500, pollInterval: 100 }
});

watcher.on('add', (p) => sseBroadcast('fs', { kind: 'add', path: path.relative(ARTIFACTS_ROOT, p) }));
watcher.on('change', (p) => sseBroadcast('fs', { kind: 'change', path: path.relative(ARTIFACTS_ROOT, p) }));
watcher.on('unlink', (p) => sseBroadcast('fs', { kind: 'unlink', path: path.relative(ARTIFACTS_ROOT, p) }));
watcher.on('addDir', (p) => sseBroadcast('fs', { kind: 'addDir', path: path.relative(ARTIFACTS_ROOT, p) }));
watcher.on('unlinkDir', (p) => sseBroadcast('fs', { kind: 'unlinkDir', path: path.relative(ARTIFACTS_ROOT, p) }));

// --- Express ---
const app = express();

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, host: HOST, port: PORT, artifactsRoot: ARTIFACTS_ROOT });
});

app.get('/api/overview', async (_req, res) => {
  try {
    res.json(await getOverview());
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.get('/api/soc-daily', async (_req, res) => {
  try {
    const out = await getSocDaily();
    if (!out.ok) return res.status(404).json(out);
    res.json(out);
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.get('/api/agent/:agent/runs', async (req, res) => {
  try {
    const agent = req.params.agent;
    const agentDir = path.join(ARTIFACTS_ROOT, agent);
    const runs = await listDirs(agentDir);
    // Sort newest first and only expose the last 15 runs to the UI to keep things manageable.
    runs.sort().reverse();
    const limited = runs.slice(0, 15);
    res.json({
      ok: true,
      agent,
      agentName: guessAgentDisplayName(agent),
      runs: limited.map((r) => ({ run: r, ts: guessRunTimestamp(r), path: path.join(agent, r) }))
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.get('/api/run', async (req, res) => {
  try {
    const rel = String(req.query.path || '');
    if (!rel) return res.status(400).json({ ok: false, error: 'missing_path' });
    const full = safeJoin(ARTIFACTS_ROOT, rel);
    const files = await listFiles(full);
    res.json({ ok: true, path: rel, files });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e?.message || e) });
  }
});

app.get('/api/artifact', async (req, res) => {
  try {
    const rel = String(req.query.path || '');
    if (!rel) return res.status(400).json({ ok: false, error: 'missing_path' });

    const full = safeJoin(ARTIFACTS_ROOT, rel);
    const ext = path.extname(full).toLowerCase();

    if (ext === '.json') {
      res.json({ ok: true, path: rel, data: await readJson(full) });
      return;
    }

    const text = await readText(full);
    if (ext === '.md' || ext === '.markdown' || ext === '.txt') {
      res.json({ ok: true, path: rel, text, html: md.render(text) });
      return;
    }

    // Default: send as text (still safe; allowlist is artifacts root)
    res.json({ ok: true, path: rel, text });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e?.message || e) });
  }
});

app.get('/api/events', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive'
  });

  res.write(`event: hello\ndata: ${JSON.stringify({ ok: true, now: new Date().toISOString() })}\n\n`);

  sseClients.add(res);
  req.on('close', () => {
    sseClients.delete(res);
  });
});

app.use('/', express.static(PUBLIC_DIR));

app.listen(PORT, HOST, () => {
  // eslint-disable-next-line no-console
  console.log(`[secops-dashboard] listening on http://${HOST}:${PORT}`);
  console.log(`[secops-dashboard] artifacts root: ${ARTIFACTS_ROOT}`);
});
