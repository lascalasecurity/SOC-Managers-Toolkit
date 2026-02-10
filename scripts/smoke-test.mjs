#!/usr/bin/env node

// Simple smoke test for the SecOps lab on a new host.
// Checks config files, secrets, MCP connectivity, and key runners.

import fs from 'node:fs';
import path from 'node:path';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const execP = promisify(exec);
const CWD = process.env.SECURITY_LAB_CWD || process.cwd();

function log(ok, msg) {
  const tag = ok ? '[OK] ' : '[FAIL]';
  console.log(`${tag} ${msg}`);
}

function warn(msg) {
  console.log(`[WARN] ${msg}`);
}

function exists(rel) {
  return fs.existsSync(path.join(CWD, rel));
}

async function main() {
  let failed = false;

  console.log(`SecOps Lab smoke test (CWD=${CWD})`);

  // 1) Config files
  try {
    if (!exists('config/mcporter.json')) {
      log(false, 'config/mcporter.json is missing');
      failed = true;
    } else {
      const mc = JSON.parse(fs.readFileSync(path.join(CWD, 'config/mcporter.json'), 'utf8'));
      if (!mc.mcpServers || !mc.mcpServers['purple-mcp'] || !mc.mcpServers['ti-aggregator']) {
        log(false, 'config/mcporter.json does not define expected mcpServers (purple-mcp, ti-aggregator)');
        failed = true;
      } else {
        log(true, 'config/mcporter.json loaded (purple-mcp, ti-aggregator present)');
      }
    }
  } catch (e) {
    log(false, `Failed to parse config/mcporter.json: ${e.message || e}`);
    failed = true;
  }

  try {
    if (!exists('config/gateway-cron.json')) {
      log(false, 'config/gateway-cron.json is missing');
      failed = true;
    } else {
      const cron = JSON.parse(fs.readFileSync(path.join(CWD, 'config/gateway-cron.json'), 'utf8'));
      const jobs = Array.isArray(cron.jobs) ? cron.jobs : [];
      const names = new Set(jobs.map((j) => j.name));
      const expected = [
        'security-lab:security-analyst:30m',
        'security-lab:ti-digest:daily-0500',
        'security-lab:vuln-manager:daily-0700'
      ];
      const missing = expected.filter((n) => !names.has(n));
      if (missing.length) {
        log(false, `config/gateway-cron.json loaded, but missing expected jobs: ${missing.join(', ')}`);
        failed = true;
      } else {
        log(true, `config/gateway-cron.json loaded (${jobs.length} jobs, core jobs present)`);
      }
    }
  } catch (e) {
    log(false, `Failed to parse config/gateway-cron.json: ${e.message || e}`);
    failed = true;
  }

  // 2) Secrets template / env
  if (!exists('mcp/.env.local')) {
    warn('mcp/.env.local is missing (expected after copying from mcp/.env.local.example)');
  } else {
    const envText = fs.readFileSync(path.join(CWD, 'mcp/.env.local'), 'utf8');
    const requiredKeys = [
      'PURPLEMCP_CONSOLE_BASE_URL',
      'PURPLEMCP_CONSOLE_TOKEN',
      'VIRUSTOTAL_API_KEY',
      'OTX_API_KEY'
    ];
    const missing = requiredKeys.filter((k) => !new RegExp(`^${k}=.+`, 'm').test(envText));
    if (missing.length) {
      warn(`mcp/.env.local present but missing values for: ${missing.join(', ')}`);
    } else {
      log(true, 'mcp/.env.local present with core TI/Purple keys');
    }
  }

  // 3) mcporter list-tools (lightweight MCP connectivity check)
  if (exists('config/mcporter.json')) {
    try {
      const cmd = 'bash -lc "cd \"$SECURITY_LAB_CWD\" && set -a && source mcp/.env.local 2>/dev/null || true && set +a && npx -y mcporter list --config config/mcporter.json"';
      const { stdout } = await execP(cmd, {
        cwd: CWD,
        env: { ...process.env, SECURITY_LAB_CWD: CWD },
        maxBuffer: 5 * 1024 * 1024
      });
      if (stdout.includes('purple-mcp') && stdout.includes('ti-aggregator')) {
        log(true, 'mcporter list shows purple-mcp and ti-aggregator');
      } else {
        warn('mcporter list did not clearly show purple-mcp/ti-aggregator; check config/mcporter.json and mcp/.env.local');
      }
    } catch (e) {
      warn(`mcporter list-tools failed: ${e.message || e}`);
    }
  }

  // 4) Security Analyst runner smoke test (collect mode)
  if (exists('agents/security-analyst/runner.js')) {
    try {
      const cmd = 'bash -lc "cd \"$SECURITY_LAB_CWD\" && set -a && source mcp/.env.local 2>/dev/null || true && set +a && node agents/security-analyst/runner.js --mode collect"';
      await execP(cmd, {
        cwd: CWD,
        env: { ...process.env, SECURITY_LAB_CWD: CWD },
        maxBuffer: 5 * 1024 * 1024
      });
      log(true, 'Security Analyst runner (--mode collect) executed without immediate error (with mcp/.env.local loaded if present)');
    } catch (e) {
      warn(`Security Analyst runner (--mode collect) exited with error: ${e.message || e}`);
    }
  }

  // 5) Dashboard presence
  if (exists('dashboard/server.js')) {
    log(true, 'Dashboard server.js present (run with `npm run dashboard`)');
  } else {
    warn('dashboard/server.js not found; dashboard will not start');
  }

  console.log('');
  if (failed) {
    console.log('Smoke test: FAIL (see [FAIL] lines above)');
    process.exitCode = 1;
  } else {
    console.log('Smoke test: PASS (with warnings if any)');
  }
}

main().catch((err) => {
  console.error(err?.stack || String(err));
  process.exit(1);
});
