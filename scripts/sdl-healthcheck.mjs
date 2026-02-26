#!/usr/bin/env node
import path from 'node:path';

import { ensureDir, writeJson, writeText } from '../lib/fs.js';
import { runPowerQuery, getTimestampRange } from '../lib/purple.js';

const CWD = process.env.SECURITY_LAB_CWD || process.cwd();
const TZ = 'America/Los_Angeles';

function stampNow() {
  const d = new Date();
  const iso = d.toLocaleString('sv-SE', { timeZone: TZ });
  const [ymd, hms] = iso.split(' ');
  return `${ymd.replaceAll('-', '')}-${hms.replaceAll(':', '')}`;
}

function classify(err) {
  const t = String(err || '');
  if (/\/sdl\/v2\/api\/queries|\b500\b|Internal Server Error/i.test(t)) return 'sdl_5xx';
  if (/401|403|unauthorized|forbidden/i.test(t)) return 'auth';
  if (/timeout|timed out/i.test(t)) return 'timeout';
  return 'other_error';
}

async function main() {
  const stamp = stampNow();
  const outDir = path.join(CWD, 'artifacts', 'cron', 'purple-sdl-health', stamp);
  ensureDir(outDir);

  // Use Purple-provided time bounds when possible.
  const range = await getTimestampRange({ cwd: CWD, hours: 1 });
  const startIso = range?.startIso || new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const endIso = range?.endIso || new Date().toISOString();

  const query = 'events | fields timestamp, event.type | sort timestamp desc | limit 1';

  const startedAt = new Date().toISOString();
  const result = await runPowerQuery({
    cwd: CWD,
    query,
    startIso,
    endIso,
    retries: 1,
    timeoutMs: 20000
  });
  const finishedAt = new Date().toISOString();

  const ok = !(result && typeof result === 'object' && result.error);

  const doc = {
    startedAt,
    finishedAt,
    window: { startIso, endIso },
    query,
    ok,
    error: ok ? null : String(result.error),
    errorClass: ok ? null : classify(result.error),
    raw: result
  };

  writeJson(path.join(outDir, 'health.json'), doc);

  const md = [
    `# Purple SDL / PowerQuery health — ${stamp}`,
    '',
    `Window (UTC): ${startIso} → ${endIso}`,
    `Result: ${ok ? 'OK' : 'ERROR'}`,
    ok ? '' : `Error class: ${doc.errorClass}`,
    ok ? '' : `Error: ${doc.error}`,
    '',
    `Artifacts: ${path.relative(CWD, outDir)}/health.json`
  ].filter(Boolean).join('\n');

  writeText(path.join(outDir, 'summary.md'), md + '\n');
  process.stdout.write(md + '\n');

  if (!ok) process.exitCode = 2;
}

main().catch((err) => {
  process.stderr.write(String(err?.stack || err) + '\n');
  process.exitCode = 1;
});
