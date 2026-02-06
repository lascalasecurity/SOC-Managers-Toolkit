import { mcporterCall } from './mcporter.js';

/**
 * Thin JS wrappers around the ti-aggregator MCP server.
 *
 * These helpers are intentionally "dumb" (deterministic IO in/out) so the
 * reasoning agents can do the judgment calls.
 */

export async function enrichIndicator({ cwd, indicator, type = 'auto', sources }) {
  const args = { indicator, type };
  if (sources && Array.isArray(sources)) args.sources = JSON.stringify(sources);

  const r = await mcporterCall({
    cwd,
    tool: 'ti-aggregator.enrich_indicator',
    args,
    output: 'json',
    timeoutMs: 120000
  });
  return JSON.parse(r.stdout);
}

export async function bulkEnrich({ cwd, indicators, type = 'auto', sources }) {
  const args = { indicators: JSON.stringify(indicators ?? []), type };
  if (sources && Array.isArray(sources)) args.sources = JSON.stringify(sources);

  const r = await mcporterCall({
    cwd,
    tool: 'ti-aggregator.bulk_enrich',
    args,
    output: 'json',
    timeoutMs: 240000
  });
  return JSON.parse(r.stdout);
}

export async function cveReport({ cwd, cve }) {
  const r = await mcporterCall({
    cwd,
    tool: 'ti-aggregator.cve_report',
    args: { cve },
    output: 'json',
    timeoutMs: 120000
  });
  return JSON.parse(r.stdout);
}
