#!/usr/bin/env node

// doctor.mjs
// Readiness checks for standing up security-lab on a fresh host.
// Non-destructive: verifies files, env, basic toolchain, and MCP reachability.

import fs from 'node:fs';
import path from 'node:path';
import { exec as execCb } from 'node:child_process';
import { promisify } from 'node:util';

const execP = promisify(execCb);
const CWD = process.env.SECURITY_LAB_CWD || process.cwd();

function ok(msg) { console.log(`[OK] ${msg}`); }
function fail(msg) { console.log(`[FAIL] ${msg}`); }
function warn(msg) { console.log(`[WARN] ${msg}`); }

function exists(rel) {
  return fs.existsSync(path.join(CWD, rel));
}

function read(rel) {
  return fs.readFileSync(path.join(CWD, rel), 'utf8');
}

async function sh(cmd, { timeoutMs = 120000 } = {}) {
  return execP(cmd, {
    cwd: CWD,
    env: { ...process.env, SECURITY_LAB_CWD: CWD },
    timeout: timeoutMs,
    maxBuffer: 20 * 1024 * 1024
  });
}

function cronExprFromName(name) {
  // Best-effort: detect a suffix like daily-0830 or weekly-mon-0800
  const mDaily = name.match(/:daily-(\d{4})$/);
  if (mDaily) {
    const hhmm = mDaily[1];
    const hh = Number(hhmm.slice(0, 2));
    const mm = Number(hhmm.slice(2, 4));
    if (Number.isFinite(hh) && Number.isFinite(mm)) return `${mm} ${hh} * * *`;
  }
  const mWeekly = name.match(/:weekly-(mon|tue|wed|thu|fri|sat|sun)-(\d{4})$/);
  if (mWeekly) {
    const dowMap = { sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6 };
    const dow = dowMap[mWeekly[1]];
    const hhmm = mWeekly[2];
    const hh = Number(hhmm.slice(0, 2));
    const mm = Number(hhmm.slice(2, 4));
    if (Number.isFinite(dow) && Number.isFinite(hh) && Number.isFinite(mm)) return `${mm} ${hh} * * ${dow}`;
  }
  return null;
}

async function main() {
  let hardFail = false;
  console.log(`security-lab doctor (CWD=${CWD})`);

  // 0) Core files
  const requiredFiles = [
    'package.json',
    'config/mcporter.json',
    'config/gateway-cron.json',
    'dashboard/server.js'
  ];
  for (const f of requiredFiles) {
    if (exists(f)) ok(`${f} present`);
    else { fail(`${f} missing`); hardFail = true; }
  }

  // 1) Node / npm
  try {
    const { stdout } = await sh('node -v', { timeoutMs: 5000 });
    ok(`node present: ${stdout.trim()}`);
  } catch (e) {
    fail(`node missing or not runnable: ${e.message || e}`);
    hardFail = true;
  }

  try {
    const { stdout } = await sh('npm -v', { timeoutMs: 5000 });
    ok(`npm present: ${stdout.trim()}`);
  } catch (e) {
    warn(`npm missing or not runnable (dashboard/installs may fail): ${e.message || e}`);
  }

  // 2) OpenClaw (optional but expected for cron)
  try {
    const { stdout } = await sh('openclaw status', { timeoutMs: 10000 });
    ok('openclaw reachable (status OK)');
    if (!stdout) {
      // ignore
    }
  } catch (e) {
    warn(`openclaw not reachable (cron deployment won’t work yet): ${e.message || e}`);
  }

  // 3) uvx presence (purple-mcp stdio launcher)
  try {
    const { stdout } = await sh('command -v uvx', { timeoutMs: 5000 });
    if (stdout.trim()) ok(`uvx present: ${stdout.trim()}`);
    else warn('uvx not found (purple-mcp stdio launch may fail depending on mcporter config)');
  } catch {
    warn('uvx not found (purple-mcp stdio launch may fail depending on mcporter config)');
  }

  // 4) Secrets/env
  if (!exists('mcp/.env.local')) {
    warn('mcp/.env.local missing (copy from mcp/.env.local.example and fill in keys)');
  } else {
    ok('mcp/.env.local present');
    const envText = read('mcp/.env.local');
    const required = ['PURPLEMCP_CONSOLE_BASE_URL', 'PURPLEMCP_CONSOLE_TOKEN'];
    const missing = required.filter((k) => !new RegExp(`^${k}=.+`, 'm').test(envText));
    if (missing.length) warn(`mcp/.env.local missing values for: ${missing.join(', ')}`);
    else ok('Purple MCP env vars present (base URL + token)');
  }

  // 5) Cron spec sanity: schedule drift vs job name (best-effort)
  try {
    const cron = JSON.parse(read('config/gateway-cron.json'));
    const jobs = Array.isArray(cron.jobs) ? cron.jobs : [];
    const drifts = [];
    for (const j of jobs) {
      const expected = cronExprFromName(j.name);
      const actual = j?.schedule?.expr;
      if (expected && actual && expected !== actual) {
        drifts.push(`${j.name}: expected ${expected} got ${actual}`);
      }
    }
    if (drifts.length) {
      warn(`gateway-cron.json schedule/name drift detected:\n- ${drifts.join('\n- ')}`);
    } else {
      ok('gateway-cron.json schedule expressions look consistent with job names (where name encodes time)');
    }
  } catch (e) {
    warn(`Could not validate gateway-cron.json schedule/name consistency: ${e.message || e}`);
  }

  // 6) MCP connectivity (mcporter)
  if (exists('config/mcporter.json')) {
    try {
      const { stdout } = await sh('npx -y mcporter list --config config/mcporter.json', { timeoutMs: 60000 });
      if (stdout.includes('purple-mcp') && stdout.includes('ti-aggregator')) {
        ok('mcporter list shows purple-mcp and ti-aggregator');
      } else {
        warn('mcporter list ran, but did not clearly show purple-mcp/ti-aggregator (check config/mcporter.json)');
      }
    } catch (e) {
      warn(`mcporter list failed: ${e.message || e}`);
    }

    // Purple smoke (requires env)
    try {
      const { stdout } = await sh('bash -lc "cd \"$SECURITY_LAB_CWD\" && set -a && source mcp/.env.local && set +a && npx -y mcporter call --config config/mcporter.json purple-mcp.list_alerts --output json"', { timeoutMs: 120000 });
      // Just sanity check JSON-ish
      if (stdout.trim().startsWith('{') || stdout.trim().startsWith('[')) ok('purple-mcp.list_alerts succeeded');
      else warn('purple-mcp.list_alerts returned non-JSON output (check token/base URL)');
    } catch (e) {
      warn(`purple-mcp.list_alerts failed (likely env/token/base URL): ${e.message || e}`);
    }

    // TI aggregator smoke (no key required for some sources, but may still fail)
    try {
      await sh('bash -lc "cd \"$SECURITY_LAB_CWD\" && set -a && source mcp/.env.local 2>/dev/null || true && set +a && npx -y mcporter call --config config/mcporter.json ti-aggregator.fetch_feed_snapshot sources=kev limit=1 days=7 --output json"', { timeoutMs: 120000 });
      ok('ti-aggregator.fetch_feed_snapshot (KEV) succeeded');
    } catch (e) {
      warn(`ti-aggregator.fetch_feed_snapshot failed: ${e.message || e}`);
    }
  }

  console.log('');
  if (hardFail) {
    console.log('doctor: FAIL (fix [FAIL] items above)');
    process.exitCode = 1;
  } else {
    console.log('doctor: PASS (warnings may still require attention)');
  }
}

main().catch((err) => {
  console.error(err?.stack || String(err));
  process.exit(1);
});
