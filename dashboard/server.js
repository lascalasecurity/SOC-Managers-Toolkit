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

async function getLatestRun(agent) {
  const agentDir = path.join(ARTIFACTS_ROOT, agent);
  const dirs = await listDirs(agentDir);
  if (!dirs.length) return null;

  // Sort lexicographically descending works for YYYYMMDD(-HHMM) stamps.
  dirs.sort().reverse();
  const latest = dirs[0];
  const full = path.join(agentDir, latest);
  const files = await listFiles(full);

  // prefer report.md, fall back to digest.md
  const preferred = files.includes('report.md') ? 'report.md' : files.includes('digest.md') ? 'digest.md' : null;

  return {
    id: idFromPath(path.join(agent, latest)),
    agent,
    agentName: guessAgentDisplayName(agent),
    run: latest,
    ts: guessRunTimestamp(latest),
    path: path.join(agent, latest),
    files,
    primaryMarkdown: preferred
  };
}

async function getOverview() {
  const agents = await listDirs(ARTIFACTS_ROOT);
  agents.sort();

  const tiles = [];
  for (const a of agents) {
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

app.get('/api/agent/:agent/runs', async (req, res) => {
  try {
    const agent = req.params.agent;
    const agentDir = path.join(ARTIFACTS_ROOT, agent);
    const runs = await listDirs(agentDir);
    runs.sort().reverse();
    res.json({ ok: true, agent, agentName: guessAgentDisplayName(agent), runs: runs.map((r) => ({ run: r, ts: guessRunTimestamp(r), path: path.join(agent, r) })) });
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
