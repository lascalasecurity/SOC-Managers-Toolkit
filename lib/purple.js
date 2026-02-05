import { mcporterCall } from './mcporter.js';

export async function listAlerts({ cwd, first = 50 }) {
  const r = await mcporterCall({ cwd, tool: 'purple-mcp.list_alerts', args: { first }, output: 'json' });
  return JSON.parse(r.stdout);
}

export async function getAlert({ cwd, alertId }) {
  const r = await mcporterCall({ cwd, tool: 'purple-mcp.get_alert', args: { alert_id: alertId }, output: 'json' });
  return JSON.parse(r.stdout);
}

export async function getAlertNotes({ cwd, alertId }) {
  const r = await mcporterCall({ cwd, tool: 'purple-mcp.get_alert_notes', args: { alert_id: alertId }, output: 'json' });
  return JSON.parse(r.stdout);
}

export async function getTimestampRange({ cwd, hours = 24 }) {
  const r = await mcporterCall({ cwd, tool: 'purple-mcp.get_timestamp_range', args: { hours }, output: 'json' });
  return JSON.parse(r.stdout);
}

export async function purpleAi({ cwd, query }) {
  // purple_ai expects param name: query
  const r = await mcporterCall({ cwd, tool: 'purple-mcp.purple_ai', args: { query }, output: 'json' });
  try { return JSON.parse(r.stdout); } catch { return { text: r.stdout }; }
}

export async function runPowerQuery({ cwd, query, startMs, endMs }) {
  const args = { query };
  if (startMs != null || endMs != null) {
    args.start_timestamp = startMs;
    args.end_timestamp = endMs;
  }
  const r = await mcporterCall({ cwd, tool: 'purple-mcp.powerquery', args, output: 'json', timeoutMs: 300000 });
  return JSON.parse(r.stdout);
}

export async function listVulns({ cwd, first = 50 }) {
  const r = await mcporterCall({ cwd, tool: 'purple-mcp.list_vulnerabilities', args: { first }, output: 'json' });
  return JSON.parse(r.stdout);
}
