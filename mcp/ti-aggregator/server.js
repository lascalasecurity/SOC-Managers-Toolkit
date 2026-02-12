#!/usr/bin/env node
/**
 * TI Aggregator MCP Server (local stdio)
 *
 * v0 goals:
 * - Read-only enrichment for: ip/domain/url/hash/cve
 * - Fan-out to a few providers via direct HTTP APIs
 * - Return a normalized object (verdict/scores/evidence + rawRefs)
 *
 * Providers implemented:
 * - OTX (AlienVault)           (requires OTX_API_KEY)
 * - GreyNoise community        (optional GREYNOISE_API_KEY)
 * - CISA KEV (public feed)     (no key; cached on disk)
 * - abuse.ch URLhaus (public)  (no key for these endpoints)
 * - VirusTotal (optional)      (VIRUSTOTAL_API_KEY)
 */

const fs = require('fs');
const path = require('path');

const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const z = require('zod/v4');

const { env } = process;

const ROOT_DIR = path.resolve(__dirname, '..', '..'); // security-lab/
const CACHE_DIR = path.join(__dirname, 'cache');
const ARTIFACTS_DIR = path.join(ROOT_DIR, 'artifacts', 'ti');

if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
if (!fs.existsSync(ARTIFACTS_DIR)) fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function readJsonIfFresh(p, maxAgeMs) {
  try {
    const stat = fs.statSync(p);
    const ageMs = Date.now() - stat.mtimeMs;
    if (ageMs > maxAgeMs) return null;
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

function shouldWriteArtifacts() {
  return env.TI_AGG_WRITE_ARTIFACTS === '1' || env.TI_AGG_WRITE_ARTIFACTS === 'true';
}

function safeFileComponent(s) {
  return String(s).replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 160);
}

function writeArtifact(filename, obj) {
  if (!shouldWriteArtifacts()) return;
  const p = path.join(ARTIFACTS_DIR, filename);
  fs.writeFileSync(p, JSON.stringify(obj, null, 2) + '\n');
}

function guessType(ind) {
  if (/^CVE-\d{4}-\d{4,7}$/i.test(ind)) return 'cve';
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ind)) return 'ip';
  if (/^https?:\/\//i.test(ind)) return 'url';
  if (/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(ind)) return 'hash';
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(ind)) return 'email';
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(ind)) return 'domain';
  return 'auto';
}

function normalizeVerdict(scores) {
  const vals = Object.values(scores || {}).filter((v) => typeof v === 'number');
  const max = vals.length ? Math.max(...vals) : 0;
  if (max >= 70) return 'malicious';
  if (max >= 40) return 'suspicious';
  return 'unknown';
}

async function fetchOTX(indicator, type) {
  const key = env.OTX_API_KEY;
  if (!key) return { score: null, evidence: [], raw: null, error: 'OTX_API_KEY missing' };

  let url;
  switch (type) {
    case 'ip': url = `https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(indicator)}/general`; break;
    case 'domain': url = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(indicator)}/general`; break;
    case 'url': url = `https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(indicator)}/general`; break;
    case 'hash': url = `https://otx.alienvault.com/api/v1/indicators/file/${encodeURIComponent(indicator)}/general`; break;
    case 'email': url = `https://otx.alienvault.com/api/v1/indicators/email/${encodeURIComponent(indicator)}/general`; break;
    default: return { score: null, evidence: [], raw: null, error: `Unsupported type for OTX: ${type}` };
  }

  const res = await fetch(url, { headers: { 'X-OTX-API-KEY': key } });
  if (!res.ok) return { score: null, evidence: [], raw: null, error: `OTX ${res.status}` };
  const data = await res.json();

  const pulses = data?.pulse_info?.pulses || [];
  const score = Math.min(100, pulses.length * 10);
  const evidence = pulses.slice(0, 5).map((p) => ({ source: 'otx', kind: 'pulse', value: p.name, timestamp: p.created }));

  return { score, evidence, raw: data };
}

async function fetchGreyNoise(indicator, type) {
  if (type !== 'ip') return { score: null, evidence: [], raw: null };

  const url = `https://api.greynoise.io/v3/community/${encodeURIComponent(indicator)}`;
  const headers = { Accept: 'application/json' };
  if (env.GREYNOISE_API_KEY) headers.key = env.GREYNOISE_API_KEY;

  const res = await fetch(url, { headers });
  if (!res.ok) return { score: null, evidence: [], raw: null, error: `GreyNoise ${res.status}` };
  const data = await res.json();

  const classification = data.classification; // malicious|benign|unknown
  const map = { malicious: 80, unknown: 30, benign: 10 };
  const score = map[classification] ?? 0;

  const evidence = [];
  if (data.name) evidence.push({ source: 'greynoise', kind: 'actor', value: data.name });
  if (data.last_seen) evidence.push({ source: 'greynoise', kind: 'last_seen', value: data.last_seen });

  return { score, evidence, raw: data };
}

async function fetchCISAKev(cve) {
  const cacheFile = path.join(CACHE_DIR, 'cisa_kev.json');
  let kev;

  try {
    const stat = fs.existsSync(cacheFile) ? fs.statSync(cacheFile) : null;
    const ageMs = stat ? (Date.now() - stat.mtimeMs) : Infinity;
    if (ageMs > 6 * 60 * 60 * 1000) throw new Error('stale');
    kev = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
  } catch {
    const res = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
    if (!res.ok) return { score: null, evidence: [], raw: null, error: `KEV ${res.status}` };
    kev = await res.json();
    fs.writeFileSync(cacheFile, JSON.stringify(kev));
  }

  const items = kev?.vulnerabilities || [];
  const hit = items.find((v) => (v.cveID || '').toUpperCase() === cve.toUpperCase());

  if (!hit) return { score: 0, evidence: [], raw: { knownExploited: false } };
  return {
    score: 85,
    evidence: [{ source: 'kev', kind: 'known_exploited', value: true, timestamp: hit.dateAdded }],
    raw: { knownExploited: true, hit }
  };
}

async function fetchAbuseCH(indicator, type) {
  // abuse.ch URLhaus
  if (type === 'url') {
    const res = await fetch('https://urlhaus.abuse.ch/api/v1/url/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ url: indicator })
    });
    if (!res.ok) return { score: null, evidence: [], raw: null, error: `abuse.ch ${res.status}` };
    const data = await res.json();

    const score = data.url_status === 'online' || data.url_status === 'offline' ? 70 : 0;
    const evidence = [];
    if (data.threat) evidence.push({ source: 'abuse.ch', kind: 'threat', value: data.threat });

    return { score, evidence, raw: data };
  }

  if (type === 'domain') {
    const res = await fetch('https://urlhaus.abuse.ch/api/v1/host/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ host: indicator })
    });
    if (!res.ok) return { score: null, evidence: [], raw: null, error: `abuse.ch ${res.status}` };
    const data = await res.json();

    const listed = Array.isArray(data.urls) && data.urls.length > 0;
    return {
      score: listed ? 70 : 0,
      evidence: listed ? [{ source: 'abuse.ch', kind: 'listed_count', value: data.urls.length }] : [],
      raw: data
    };
  }

  return { score: null, evidence: [], raw: null };
}

async function fetchAbuseIPDB(indicator, type) {
  // AbuseIPDB is IP-reputation focused; we treat it as an IP-only enrichment source.
  if (type !== 'ip') return { score: null, evidence: [], raw: null };

  const key = env.ABUSEIPDB_API_KEY;
  if (!key) return { score: null, evidence: [], raw: null, error: 'ABUSEIPDB_API_KEY missing' };

  const url = 'https://api.abuseipdb.com/api/v2/check';
  const params = new URLSearchParams({ ipAddress: indicator, maxAgeInDays: '90' });

  const res = await fetch(url, {
    method: 'GET',
    headers: {
      Key: key,
      Accept: 'application/json'
    },
    body: undefined, // GET with query params only
  }).catch((e) => ({ ok: false, status: 0, _err: e }));

  if (!res.ok) return { score: null, evidence: [], raw: null, error: `AbuseIPDB ${res.status}` };
  const data = await res.json();

  const attr = data?.data || {};
  const score = typeof attr.abuseConfidenceScore === 'number' ? Math.min(100, attr.abuseConfidenceScore) : null;
  const reports = typeof attr.totalReports === 'number' ? attr.totalReports : null;

  const evidence = [];
  if (score != null) evidence.push({ source: 'abuseipdb', kind: 'confidence', value: score });
  if (reports != null) evidence.push({ source: 'abuseipdb', kind: 'reports', value: reports });
  if (attr.lastReportedAt) evidence.push({ source: 'abuseipdb', kind: 'last_reported_at', value: attr.lastReportedAt });

  return { score, evidence, raw: data };
}

async function fetchVirusTotal(indicator, type) {
  const key = env.VIRUSTOTAL_API_KEY;
  if (!key) return { score: null, evidence: [], raw: null, error: 'VIRUSTOTAL_API_KEY missing' };

  const headers = { 'x-apikey': key };
  let url;

  switch (type) {
    case 'ip': url = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(indicator)}`; break;
    case 'domain': url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(indicator)}`; break;
    case 'url': {
      // URL endpoints use a base64url id
      const id = Buffer.from(indicator)
        .toString('base64')
        .replace(/=+$/, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
      url = `https://www.virustotal.com/api/v3/urls/${id}`;
      break;
    }
    case 'hash': url = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(indicator)}`; break;
    default: return { score: null, evidence: [], raw: null, error: `Unsupported type for VT: ${type}` };
  }

  const res = await fetch(url, { headers });
  if (!res.ok) return { score: null, evidence: [], raw: null, error: `VT ${res.status}` };
  const data = await res.json();

  const stats = data?.data?.attributes?.last_analysis_stats || {};
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const total = Object.values(stats).reduce((a, b) => a + b, 0) || 1;
  const score = Math.min(100, Math.round(((malicious * 2 + suspicious) / total) * 100));

  const evidence = [];
  if (malicious) evidence.push({ source: 'virustotal', kind: 'malicious_votes', value: malicious });

  return { score, evidence, raw: data };
}

async function enrichIndicator({ indicator, type = 'auto', sources = ['otx', 'greynoise', 'kev', 'abusech', 'abuseipdb', 'virustotal'] }) {
  if (!indicator || typeof indicator !== 'string') throw new Error('indicator must be a non-empty string');
  const t = type === 'auto' ? guessType(indicator) : type;
  const enabled = new Set(sources);

  const scores = {};
  const evidence = [];
  const raw = {};
  const errors = {};

  if (enabled.has('otx')) {
    try {
      const r = await fetchOTX(indicator, t);
      if (r.score != null) scores.otx = r.score;
      evidence.push(...(r.evidence || []));
      raw.otx = r.raw;
      if (r.error) errors.otx = r.error;
    } catch (e) {
      errors.otx = String(e);
    }
    await sleep(100);
  }

  if (enabled.has('greynoise')) {
    try {
      const r = await fetchGreyNoise(indicator, t);
      if (r.score != null) scores.greynoise = r.score;
      evidence.push(...(r.evidence || []));
      raw.greynoise = r.raw;
      if (r.error) errors.greynoise = r.error;
    } catch (e) {
      errors.greynoise = String(e);
    }
    await sleep(100);
  }

  if (enabled.has('kev') && t === 'cve') {
    try {
      const r = await fetchCISAKev(indicator);
      if (r.score != null) scores.kev = r.score;
      evidence.push(...(r.evidence || []));
      raw.kev = r.raw;
      if (r.error) errors.kev = r.error;
    } catch (e) {
      errors.kev = String(e);
    }
  }

  if (enabled.has('abusech')) {
    try {
      const r = await fetchAbuseCH(indicator, t);
      if (r.score != null) scores.abusech = r.score;
      evidence.push(...(r.evidence || []));
      raw.abusech = r.raw;
      if (r.error) errors.abusech = r.error;
    } catch (e) {
      errors.abusech = String(e);
    }
    await sleep(100);
  }

  if (enabled.has('abuseipdb')) {
    try {
      const r = await fetchAbuseIPDB(indicator, t);
      if (r.score != null) scores.abuseipdb = r.score;
      evidence.push(...(r.evidence || []));
      raw.abuseipdb = r.raw;
      if (r.error) errors.abuseipdb = r.error;
    } catch (e) {
      errors.abuseipdb = String(e);
    }
    await sleep(100);
  }

  if (enabled.has('virustotal')) {
    try {
      const r = await fetchVirusTotal(indicator, t);
      if (r.score != null) scores.virustotal = r.score;
      evidence.push(...(r.evidence || []));
      raw.virustotal = r.raw;
      if (r.error) errors.virustotal = r.error;
    } catch (e) {
      errors.virustotal = String(e);
    }
    await sleep(100);
  }

  const out = {
    indicator,
    type: t,
    verdict: normalizeVerdict(scores),
    scores,
    evidence,
    rawRefs: {
      otx: !!raw.otx,
      greynoise: !!raw.greynoise,
      kev: !!raw.kev,
      abusech: !!raw.abusech,
      abuseipdb: !!raw.abuseipdb,
      virustotal: !!raw.virustotal
    },
    errors: Object.keys(errors).length ? errors : undefined,
    normalizedAt: new Date().toISOString()
  };

  writeArtifact(`ti_${safeFileComponent(indicator)}.json`, out);
  return out;
}

async function bulkEnrich({ indicators, type = 'auto', sources = ['otx', 'greynoise', 'kev', 'abusech', 'abuseipdb', 'virustotal'], concurrency = 4 }) {
  let list = indicators;
  if (typeof list === 'string') {
    const s = list.trim();
    try {
      const parsed = JSON.parse(s);
      if (Array.isArray(parsed)) list = parsed;
      else list = s.split(',').map((x) => x.trim()).filter(Boolean);
    } catch {
      list = s.split(',').map((x) => x.trim()).filter(Boolean);
    }
  }
  if (!Array.isArray(list)) throw new Error('indicators must be an array (or JSON/comma-separated string)');

  const c = Math.max(1, Math.min(16, Number(concurrency) || 4));

  const indicatorsArr = list;

  const out = new Array(indicatorsArr.length);
  let i = 0;

  async function worker() {
    while (true) {
      const idx = i++;
      if (idx >= indicatorsArr.length) return;
      const indicator = indicatorsArr[idx];
      try {
        out[idx] = await enrichIndicator({ indicator, type, sources });
      } catch (e) {
        out[idx] = { indicator, type: type === 'auto' ? guessType(indicator) : type, verdict: 'unknown', scores: {}, evidence: [], errors: { bulk: String(e) }, normalizedAt: new Date().toISOString() };
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(c, indicatorsArr.length || 1) }, worker));

  const batch = {
    count: out.length,
    results: out,
    normalizedAt: new Date().toISOString()
  };
  writeArtifact(`ti_batch_${Date.now()}.json`, batch);
  return batch;
}

// --- Feed snapshot helpers (v0) ---

async function fetchOtxPulseSnapshot({ limit = 30 }) {
  const key = env.OTX_API_KEY;
  if (!key) return { pulses: [], error: 'OTX_API_KEY missing' };

  const cacheFile = path.join(CACHE_DIR, 'otx_pulses.json');
  const cached = readJsonIfFresh(cacheFile, 60 * 60 * 1000);
  if (cached) return { pulses: cached, cached: true };

  // NOTE: OTX API shape can vary by endpoint/account; we use a simple, best-effort endpoint.
  // If this endpoint returns a different envelope, we still attempt to extract an array.
  const url = `https://otx.alienvault.com/api/v1/pulses/subscribed?limit=${encodeURIComponent(String(limit))}`;
  const res = await fetch(url, { headers: { 'X-OTX-API-KEY': key } });
  if (!res.ok) return { pulses: [], error: `OTX pulses ${res.status}` };

  const data = await res.json();
  const pulses = Array.isArray(data?.results) ? data.results : Array.isArray(data?.pulses) ? data.pulses : Array.isArray(data) ? data : [];

  try {
    fs.writeFileSync(cacheFile, JSON.stringify(pulses));
  } catch {
    // ignore cache write errors
  }

  return { pulses, cached: false };
}

function normalizePulseIndicators(pulse) {
  const out = [];
  const created = pulse?.created || pulse?.created_at || pulse?.modified || null;
  const context = pulse?.name || pulse?.title || pulse?.description || null;
  const tags = Array.isArray(pulse?.tags) ? pulse.tags : null;

  // OTX typically uses objects like {indicator, type}.
  const indicators = Array.isArray(pulse?.indicators) ? pulse.indicators : [];
  for (const ind of indicators) {
    const indicator = String(ind?.indicator || ind?.value || '').trim();
    if (!indicator) continue;
    const type = String(ind?.type || guessType(indicator) || 'auto').toLowerCase();
    out.push({
      indicator,
      type,
      context,
      tags,
      sources: ['otx'],
      firstSeen: created
    });
  }

  return out;
}

async function fetchFeedSnapshot({ sources = ['kev', 'otx'], limit = 100, days = 7 }) {
  const enabled = new Set(sources);
  const items = [];
  const errors = {};

  // 1) CISA KEV (CVE-only)
  if (enabled.has('kev')) {
    try {
      const cacheFile = path.join(CACHE_DIR, 'cisa_kev.json');
      let kev = readJsonIfFresh(cacheFile, 6 * 60 * 60 * 1000);
      if (!kev) {
        const res = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
        if (!res.ok) throw new Error(`KEV ${res.status}`);
        kev = await res.json();
        try { fs.writeFileSync(cacheFile, JSON.stringify(kev)); } catch {}
      }

      const windowMs = Math.max(1, Number(days) || 7) * 24 * 60 * 60 * 1000;
      const cutoff = Date.now() - windowMs;
      const vulns = Array.isArray(kev?.vulnerabilities) ? kev.vulnerabilities : [];
      for (const v of vulns) {
        const cve = String(v?.cveID || '').trim();
        if (!cve) continue;
        const dateAdded = v?.dateAdded ? new Date(v.dateAdded).getTime() : null;
        if (dateAdded && dateAdded < cutoff) continue;
        items.push({
          indicator: cve,
          type: 'cve',
          context: v?.vulnerabilityName || v?.shortDescription || null,
          tags: ['kev'],
          sources: ['kev'],
          firstSeen: v?.dateAdded || null
        });
        if (items.length >= limit) break;
      }
    } catch (e) {
      errors.kev = String(e?.message || e);
    }
  }

  // 2) OTX pulses → indicators
  if (enabled.has('otx') && items.length < limit) {
    try {
      const snap = await fetchOtxPulseSnapshot({ limit: Math.min(50, Math.max(1, Number(limit) || 30)) });
      if (snap.error) errors.otx = snap.error;

      for (const p of snap.pulses || []) {
        const inds = normalizePulseIndicators(p);
        for (const i of inds) {
          items.push(i);
          if (items.length >= limit) break;
        }
        if (items.length >= limit) break;
      }
    } catch (e) {
      errors.otx = String(e?.message || e);
    }
  }

  // Dedupe
  const seen = new Set();
  const deduped = [];
  for (const i of items) {
    const k = `${String(i.type || 'auto').toLowerCase()}:${i.indicator}`;
    if (seen.has(k)) continue;
    seen.add(k);
    deduped.push(i);
  }

  return {
    schema: 'ti-aggregator:feed-snapshot:v0',
    generatedAt: new Date().toISOString(),
    sources: Array.from(enabled),
    limit: Number(limit) || 100,
    days: Number(days) || 7,
    count: deduped.length,
    items: deduped,
    errors: Object.keys(errors).length ? errors : undefined
  };
}

// --- MCP server wiring ---
const mcpServer = new McpServer({ name: 'ti-aggregator', version: '0.0.3' });

mcpServer.registerTool(
  'enrich_indicator',
  {
    description: 'Enrich an indicator from multiple TI sources and normalize the result',
    inputSchema: {
      indicator: z.string().describe('Indicator value (ip/domain/url/hash/cve)'),
      type: z.enum(['auto', 'ip', 'domain', 'url', 'hash', 'email', 'cve']).default('auto'),
      sources: z.array(z.string()).default(['otx', 'greynoise', 'kev', 'abusech', 'virustotal']),
      maxPerSource: z.number().int().min(1).max(50).default(1)
    }
  },
  async (args) => {
    const res = await enrichIndicator(args);
    return { content: [{ type: 'text', text: JSON.stringify(res, null, 2) }] };
  }
);

mcpServer.registerTool(
  'bulk_enrich',
  {
    description: 'Enrich a list of indicators (fan-out + normalized results)',
    inputSchema: {
      indicators: z.union([z.array(z.string()), z.string()]).describe('List of indicators (array or JSON/comma-separated string)'),
      type: z.enum(['auto', 'ip', 'domain', 'url', 'hash', 'email', 'cve']).default('auto'),
      sources: z.array(z.string()).default(['otx', 'greynoise', 'kev', 'abusech', 'virustotal']),
      concurrency: z.number().int().min(1).max(16).default(4)
    }
  },
  async (args) => ({ content: [{ type: 'text', text: JSON.stringify(await bulkEnrich(args), null, 2) }] })
);

mcpServer.registerTool(
  'fetch_feed_snapshot',
  {
    description: 'Fetch a normalized TI feed snapshot (v0: CISA KEV + OTX pulses → indicators). Intended for collectors; not a scoring/judgment tool.',
    inputSchema: {
      sources: z.array(z.enum(['kev', 'otx'])).default(['kev', 'otx']),
      limit: z.number().int().min(1).max(500).default(100),
      days: z.number().int().min(1).max(90).default(7)
    }
  },
  async (args) => ({ content: [{ type: 'text', text: JSON.stringify(await fetchFeedSnapshot(args), null, 2) }] })
);

mcpServer.registerTool(
  'ip_reputation',
  {
    description: 'Reputation for an IP address (wrapper over enrich_indicator)',
    inputSchema: { ip: z.string() }
  },
  async ({ ip }) => ({ content: [{ type: 'text', text: JSON.stringify(await enrichIndicator({ indicator: ip, type: 'ip' }), null, 2) }] })
);

mcpServer.registerTool(
  'domain_report',
  {
    description: 'Report for a domain (wrapper over enrich_indicator)',
    inputSchema: { domain: z.string() }
  },
  async ({ domain }) => ({ content: [{ type: 'text', text: JSON.stringify(await enrichIndicator({ indicator: domain, type: 'domain' }), null, 2) }] })
);

mcpServer.registerTool(
  'url_report',
  {
    description: 'Report for a URL (wrapper over enrich_indicator)',
    inputSchema: { url: z.string() }
  },
  async ({ url }) => ({ content: [{ type: 'text', text: JSON.stringify(await enrichIndicator({ indicator: url, type: 'url' }), null, 2) }] })
);

mcpServer.registerTool(
  'file_report',
  {
    description: 'Report for a file hash (wrapper over enrich_indicator)',
    inputSchema: { hash: z.string() }
  },
  async ({ hash }) => ({ content: [{ type: 'text', text: JSON.stringify(await enrichIndicator({ indicator: hash, type: 'hash' }), null, 2) }] })
);

mcpServer.registerTool(
  'cve_report',
  {
    description: 'Report for a CVE (KEV check)',
    inputSchema: { cve: z.string() }
  },
  async ({ cve }) => {
    const kev = await fetchCISAKev(cve);
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            cve,
            knownExploited: !!kev?.raw?.knownExploited,
            verdict: normalizeVerdict(kev.score != null ? { kev: kev.score } : {}),
            scores: kev.score != null ? { kev: kev.score } : {},
            evidence: kev.evidence || [],
            rawRefs: { kev: kev.raw }
          }, null, 2)
        }
      ]
    };
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await mcpServer.connect(transport);
}

main().catch((err) => {
  // IMPORTANT: log to stderr; stdout is reserved for MCP framing
  console.error('ti-aggregator server error:', err);
  process.exit(1);
});
