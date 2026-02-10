#!/usr/bin/env node

// apply-cron-spec.mjs
// Sync OpenClaw Gateway cron jobs to match config/gateway-cron.json

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const CWD = process.env.SECURITY_LAB_CWD || process.cwd();
const CRON_SPEC_PATH = path.join(CWD, 'config', 'gateway-cron.json');

function loadJson(p) {
  const raw = fs.readFileSync(p, 'utf8');
  return JSON.parse(raw);
}

async function main() {
  if (!fs.existsSync(CRON_SPEC_PATH)) {
    console.error(`cron spec not found: ${CRON_SPEC_PATH}`);
    process.exit(1);
  }

  const spec = loadJson(CRON_SPEC_PATH);
  const desiredJobs = Array.isArray(spec.jobs) ? spec.jobs : [];

  // Use OpenClaw cron tool via environment (this script is meant to be run from the agent context).
  // We rely on the agent to call the `cron` tool, so here we just print what *should* happen.
  // The main agent will translate this into actual cron.add/cron.update calls.

  const out = {
    kind: 'gateway-cron-spec',
    cwd: CWD,
    specPath: path.relative(CWD, CRON_SPEC_PATH),
    jobs: desiredJobs
  };

  process.stdout.write(JSON.stringify(out, null, 2));
}

main().catch((err) => {
  console.error(err?.stack || String(err));
  process.exit(1);
});
