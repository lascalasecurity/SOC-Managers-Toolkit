import fs from 'node:fs/promises';
import path from 'node:path';

import { ensureDir, writeJson, writeText } from '../../lib/fs.js';
import { purpleAi } from '../../lib/purple.js';

const CWD = process.env.SECURITY_LAB_CWD || process.cwd();
const TZ = 'America/Los_Angeles';

function ymdNow() {
  const d = new Date();
  const iso = d.toLocaleString('sv-SE', { timeZone: TZ });
  return iso.split(' ')[0].replaceAll('-', '');
}

async function main() {
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

  // Optional: allow single-hypothesis test run
  const only = process.argv.includes('--only') ? process.argv[process.argv.indexOf('--only') + 1] : null;
  const selectedHyps = only ? hypotheses.filter(h => h.id === only) : hypotheses;

  const responses = [];

  for (const h of selectedHyps) {
    const prompt = [
      `You are a threat hunter working inside SentinelOne Purple.`,
      `You have access to the environment telemetry and can run PowerQuery under the hood.`,
      '',
      `Time window (UTC): ${window.startIso} -> ${window.endIso}.`,
      primaryHost ? `Primary host to prioritize: ${primaryHost}.` : `No primary host identified from alerts; prioritize any hosts involved in the alerts.`,
      `Motivation alert IDs (sample): ${motivationIds.length ? motivationIds.join(', ') : '<none>'}`,
      '',
      `Hypothesis ${h.id}: ${h.title}`,
      `${h.description}`,
      '',
      `Task: Hunt and return the ANSWER (not the query). You should run whatever internal queries you need.`,
      `Return a concise markdown report with this structure:`,
      `# ${h.id} Result`,
      `- Status: no_evidence | suspicious | positive_hit | inconclusive`,
      `- Confidence: low | medium | high`,
      `- Evidence: bullet list with concrete details (host, timestamp, process/cmdline, parent, user, remote_ip/domain/port, file path)`,
      `- Notes/limitations: any query/runtime limitations`,
      '',
      `If there are too many results, summarize patterns and include 3-10 representative examples.`,
      `If you cannot retrieve row-level details, say so explicitly and downgrade confidence.`
    ].join('\n');

    const ai = await purpleAi({ cwd: CWD, query: prompt });
    const text = (ai?.text ? String(ai.text) : JSON.stringify(ai, null, 2));

    responses.push({ hypothesis: h, prompt, aiRaw: ai, text });

    // small delay not needed; keep sequential
  }

  await writeJson(path.join(outDir, 'hypotheses.json'), { window, primaryHost, alertCount: alerts.length, hypotheses });
  await writeJson(path.join(outDir, 'purple_ai_hunts.json'), { window, primaryHost, responses: responses.map(r => ({ hypothesisId: r.hypothesis.id, prompt: r.prompt, aiRaw: r.aiRaw })) });

  // Human-readable report
  let md = `# Threat Hunter (daily, Purple AI execution) — ${ymd}\n\n`;
  md += `Time window (UTC): ${window.startIso} → ${window.endIso}\n`;
  md += `Alerts in window: ${alerts.length}\n`;
  md += `Primary alerted host: ${primaryHost ?? '<none>'}\n\n`;

  for (const r of responses) {
    md += `---\n\n`;
    md += `${r.text.trim()}\n\n`;
  }

  md += `Artifacts: ${path.relative(CWD, outDir)}/\n`;

  await writeText(path.join(outDir, 'report.md'), md);

  process.stdout.write(`Threat Hunter (Purple AI) — ${ymd} — hypotheses:${responses.length}\n`);
  process.stdout.write(`Artifacts: artifacts/cron/threat-hunter/${ymd}/\n`);
}

main().catch((err) => {
  process.stderr.write(String(err?.stack || err) + '\n');
  process.exitCode = 1;
});
