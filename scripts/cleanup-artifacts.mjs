#!/usr/bin/env node

import fs from 'fs';
import path from 'path';

const ROOT = process.cwd();
const CRON_DIR = path.join(ROOT, 'artifacts', 'cron');
const LOG_DIR = path.join(ROOT, 'logs');
const LOG_PATH = path.join(LOG_DIR, 'cleanup-artifacts.log');

const AGENT_RETENTION_DAYS = {
  // 30m Security Analyst runs
  'security-analyst': 60,
  // Daily jobs
  'ti-digest': 90,
  'vuln-manager': 90,
  // SOC Manager daily lives under soc-manager with YYYYMMDD; treat as daily
  'soc-manager': 90,
  // Daily hunt jobs (moved from weekly cadence)
  'threat-hunter': 90,
  'proactive-hunter': 90
};

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  process.stdout.write(line);
  try {
    if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
    fs.appendFileSync(LOG_PATH, line);
  } catch {
    // best-effort
  }
}

function parseStamp(dirName) {
  // Supports YYYYMMDD or YYYYMMDD-HHMM
  const m = String(dirName).match(/^(\d{4})(\d{2})(\d{2})(?:-(\d{2})(\d{2}))?$/);
  if (!m) return null;
  const [, y, mo, d, hh, mi] = m;
  const year = Number(y);
  const month = Number(mo) - 1;
  const day = Number(d);
  const hour = hh ? Number(hh) : 0;
  const min = mi ? Number(mi) : 0;
  return new Date(Date.UTC(year, month, day, hour, min));
}

function daysAgo(date) {
  const now = Date.now();
  return (now - date.getTime()) / (1000 * 60 * 60 * 24);
}

function rmrf(p) {
  if (!fs.existsSync(p)) return;
  const stat = fs.lstatSync(p);
  if (stat.isDirectory() && !stat.isSymbolicLink()) {
    for (const entry of fs.readdirSync(p)) {
      rmrf(path.join(p, entry));
    }
    fs.rmdirSync(p);
  } else {
    fs.unlinkSync(p);
  }
}

function main() {
  const args = new Set(process.argv.slice(2));
  const dryRun = args.has('--dry-run');

  if (!fs.existsSync(CRON_DIR)) {
    log('No artifacts/cron directory found; nothing to do.');
    return;
  }

  log(`Starting artifact cleanup (dryRun=${dryRun}) in ${CRON_DIR}`);

  const agents = fs.readdirSync(CRON_DIR, { withFileTypes: true })
    .filter((ent) => ent.isDirectory())
    .map((ent) => ent.name);

  let totalDeletedDirs = 0;

  for (const agent of agents) {
    const agentDir = path.join(CRON_DIR, agent);
    const retentionDays = AGENT_RETENTION_DAYS[agent];
    if (!retentionDays) {
      log(`Skipping agent ${agent} (no retention policy configured)`);
      continue;
    }

    log(`Processing agent ${agent} (retention ${retentionDays} days)`);

    const subdirs = fs.readdirSync(agentDir, { withFileTypes: true })
      .filter((ent) => ent.isDirectory())
      .map((ent) => ent.name)
      // sort oldest -> newest by parsed stamp, fall back to lexicographic
      .sort((a, b) => {
        const da = parseStamp(a);
        const db = parseStamp(b);
        if (da && db) return da - db;
        if (da) return -1;
        if (db) return 1;
        return a.localeCompare(b);
      });

    for (const dir of subdirs) {
      const stampDate = parseStamp(dir);

      // Hard-delete known-bad/legacy artifact folders that should never exist.
      // This prevents dashboard noise and avoids the janitor getting stuck on "unrecognized stamp".
      if (!stampDate) {
        if (agent === 'security-analyst' && dir === 'test') {
          const fullPath = path.join(agentDir, dir);
          log(`  [${agent}] deleting ${dir} (legacy test artifacts folder)`);
          if (!dryRun) {
            try {
              rmrf(fullPath);
              totalDeletedDirs++;
            } catch (e) {
              log(`  [${agent}] ERROR deleting ${dir}: ${e.message}`);
            }
          }
        } else {
          log(`  [${agent}] skipping ${dir} (unrecognized stamp)`);
        }
        continue;
      }

      const ageDays = daysAgo(stampDate);
      if (ageDays <= retentionDays) {
        continue;
      }

      const fullPath = path.join(agentDir, dir);
      log(`  [${agent}] deleting ${dir} (age=${ageDays.toFixed(1)}d > ${retentionDays}d)`);
      if (!dryRun) {
        try {
          rmrf(fullPath);
          totalDeletedDirs++;
        } catch (e) {
          log(`  [${agent}] ERROR deleting ${dir}: ${e.message}`);
        }
      }
    }
  }

  log(`Cleanup complete. Deleted directories: ${dryRun ? '0 (dry-run)' : totalDeletedDirs}`);
}

main();
