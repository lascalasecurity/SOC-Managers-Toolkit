import fs from 'node:fs/promises';
import path from 'node:path';
import { ensureDir, writeJson, writeText } from '../../lib/fs.js';
import { purpleAi, runPowerQuery } from '../../lib/purple.js';

const CWD = process.env.SECURITY_LAB_CWD || process.cwd();
const TZ = 'America/Los_Angeles';

function ymdNow() {
  const d = new Date();
  const iso = d.toLocaleString('sv-SE', { timeZone: TZ });
  return iso.split(' ')[0].replaceAll('-', '');
}

const ymd = ymdNow();
const outDir = path.join(CWD, 'artifacts', 'cron', 'threat-hunter', ymd);
await ensureDir(outDir);

const snapshotPath = path.join(outDir, 'alerts.raw.json');
const snapshot = JSON.parse(await fs.readFile(snapshotPath, 'utf8'));
const { window, alerts } = snapshot;

const hostCounts = new Map();
for (const a of alerts) {
  const h = a?.asset?.name;
  if (!h) continue;
  hostCounts.set(h, (hostCounts.get(h) || 0) + 1);
}
const primaryHost = [...hostCounts.entries()].sort((a,b)=>b[1]-a[1])[0]?.[0] || null;

const motivationIds = alerts.slice(0, 5).map(a => a.id);

const hypotheses = [
  {
    id: 'H1_shell_child_procs',
    title: 'Follow-on suspicious shell/script activity after OpenClaw-agent process spawns',
    motivation_alert_ids: motivationIds,
    entities: { host: primaryHost },
    description: `Alerts indicate suspicious process spawns by OpenClaw agent on host ${primaryHost}. Hunt for additional shells/interpreters/LOLBins spawned shortly before/after alerts (±30m), and across the full 24h window for clustering.`
  },
  {
    id: 'H2_outbound_fetch',
    title: 'Outbound network fetch/beaconing (curl/wget/python/powershell) from the alerted host',
    motivation_alert_ids: motivationIds,
    entities: { host: primaryHost },
    description: `If an agent was abused/prompt-injected, follow-on often includes outbound retrieval (curl/wget) or DNS/HTTP to external endpoints. Hunt for unusual outbound connections initiated by shells/interpreters from ${primaryHost} over 24h.`
  },
  {
    id: 'H3_persistence',
    title: 'Persistence creation (cron/systemd/SSH keys) on the alerted host',
    motivation_alert_ids: motivationIds,
    entities: { host: primaryHost },
    description: `Check for persistence artifacts created on ${primaryHost} during the 24h window: cron entries, systemd services/timers, autostart files, and SSH authorized_keys changes.`
  },
  {
    id: 'H4_lateral_movement',
    title: 'Lateral movement attempts from the alerted host (SSH) to other internal assets',
    motivation_alert_ids: motivationIds,
    entities: { host: primaryHost },
    description: `Hunt for outbound SSH connections / authentication attempts from ${primaryHost} to other assets (possible pivoting).`
  }
];

function looksLikePurpleAiError(text) {
  const t = String(text || '').trim();
  if (!t) return true;
  if (t.toLowerCase().includes('purple ai encountered an error')) return true;
  // very defensive: if it isn't even query-like, treat as bad
  if (!(t.startsWith('|') || t.toLowerCase().includes('filter('))) return true;
  return false;
}

async function genPQ({ hypothesis }) {
  const prompt = [
    `You are generating a SentinelOne Purple PowerQuery for a threat hunt in a Linux server environment.`,
    `Return ONLY the PowerQuery text (no backticks, no explanation).`,
    `Time window (UTC): ${window.startIso} -> ${window.endIso}.`,
    primaryHost ? `Scope to asset hostname: ${primaryHost}.` : `If possible, scope by the alerted asset in the query results.`,
    '',
    `Hunt goal: ${hypothesis.title}`,
    `${hypothesis.description}`,
    '',
    `REQUIREMENTS:`,
    `- Return ROW-LEVEL results (do not return summarize-only / match-count-only output).`,
    `- End the query with: | project timestamp, endpoint.name, src.process.name, src.process.cmdline, tgt.process.name, tgt.process.cmdline, username, remote_ip, remote_domain, remote_port, file.path | take 200`,
    `- If some columns don't exist, project the closest available fields and still end with | take 200.`,
    `- Do not exceed 200 rows.`,
    `- Prefer high-signal filters over broad matches to avoid caps/timeouts.`,
    `- Do NOT include markdown fences.`
  ].join('\n');

  const ai = await purpleAi({ cwd: CWD, query: prompt });
  let pq = (ai?.text || '').toString().trim();
  if (!pq && Array.isArray(ai?.content)) pq = ai.content.map(x=>x?.text||'').join('').trim();
  pq = pq.replace(/^```[a-zA-Z]*\n/, '').replace(/\n```\s*$/, '').trim();

  const bad = looksLikePurpleAiError(pq);
  return { prompt, aiRaw: ai, powerquery: pq, bad };
}

const powerqueries = [];
const results = [];

function logStep(msg) {
  process.stdout.write(`[threat-hunter] ${msg}\n`);
}

logStep(`Starting hunt: hypotheses=${hypotheses.length} window=${window.startIso}..${window.endIso} host=${primaryHost ?? '<none>'}`);

for (const h of hypotheses) {
  logStep(`HYP ${h.id}: generating PowerQuery via purple_ai...`);
  const pqGen = await genPQ({ hypothesis: h });
  powerqueries.push({ hypothesis_id: h.id, prompt: pqGen.prompt, powerquery: pqGen.powerquery, bad: pqGen.bad });

  if (pqGen.bad) {
    logStep(`HYP ${h.id}: purple_ai output invalid (skipping powerquery execution).`);
  } else {
    // Keep logs short; don't print full query by default.
    logStep(`HYP ${h.id}: executing powerquery (timeout up to 300s)...`);
  }

  let run;
  if (pqGen.bad) {
    run = { error: 'purple_ai returned non-query text or an error string', aiRaw: pqGen.aiRaw };
  } else {
    try {
      run = await runPowerQuery({ cwd: CWD, query: pqGen.powerquery, startIso: window.startIso, endIso: window.endIso });
    } catch (e) {
      run = { error: String(e?.message || e) };
    }
  }

  const rows = Array.isArray(run?.rows) ? run.rows : (Array.isArray(run?.data) ? run.data : null);
  const rowCount = rows ? rows.length : null;
  const status = run?.error ? 'ERROR' : (rowCount === 0 ? 'NO_HITS' : (rowCount != null ? `HITS:${rowCount}` : 'UNKNOWN'));
  logStep(`HYP ${h.id}: done → ${status}`);

  results.push({ hypothesis_id: h.id, query: pqGen.powerquery, result: run, rowCount });
}

logStep('Hunt complete; writing artifacts...');

await writeJson(path.join(outDir, 'hypotheses.json'), { window, primaryHost, alertCount: alerts.length, hypotheses });
await writeJson(path.join(outDir, 'powerqueries.json'), { window, powerqueries });
await writeJson(path.join(outDir, 'results.json'), { window, results });

let md = `# Threat Hunter (weekly) — ${ymd}\n\n`;
md += `Time window (UTC): ${window.startIso} → ${window.endIso}\n`;
md += `Alerts in window: ${alerts.length}\n`;
md += `Primary alerted host: ${primaryHost ?? '<none>'}\n\n`;
md += `## Hypotheses & Outcomes\n`;
for (const h of hypotheses) {
  const r = results.find(x => x.hypothesis_id === h.id);
  const obj = r?.result;
  const rows = Array.isArray(obj?.rows) ? obj.rows : (Array.isArray(obj?.data) ? obj.data : null);
  const hitCount = rows ? rows.length : null;
  const status = obj?.error ? 'ERROR' : (hitCount === 0 ? 'NO_HITS' : (hitCount != null ? `HITS:${hitCount}` : 'UNKNOWN'));
  md += `- **${h.id}** ${h.title} — ${status}\n`;
}
md += `\nArtifacts: ${path.relative(CWD, outDir)}/\n`;
await writeText(path.join(outDir, 'report.md'), md);

console.log(md);
