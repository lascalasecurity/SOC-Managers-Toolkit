import { mcporterCall } from './mcporter.js';

export async function listAlerts({ cwd, first = 50 }) {
  // NOTE: purple-mcp.list_alerts currently fails when passed pagination args like `first`.
  // To keep things robust, rely on the server-default page size and do not send `first`.
  const r = await mcporterCall({ cwd, tool: 'purple-mcp.list_alerts', args: {}, output: 'json' });
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
  // purple-mcp.get_timestamp_range commonly returns ISO strings:
  // { current_time: "...Z", offset_time: "...Z" }
  let obj;
  try { obj = JSON.parse(r.stdout); } catch { obj = { text: r.stdout }; }

  const endIso = obj?.current_time || obj?.end_time || obj?.end_datetime || null;
  const startIso = obj?.offset_time || obj?.start_time || obj?.start_datetime || null;

  const endMs = endIso ? Date.parse(endIso) : null;
  const startMs = startIso ? Date.parse(startIso) : null;

  return {
    raw: obj,
    startIso,
    endIso,
    startMs: Number.isFinite(startMs) ? startMs : null,
    endMs: Number.isFinite(endMs) ? endMs : null
  };
}

export async function purpleAi({ cwd, query }) {
  // purple_ai expects param name: query
  const r = await mcporterCall({ cwd, tool: 'purple-mcp.purple_ai', args: { query }, output: 'json' });
  try { return JSON.parse(r.stdout); } catch { return { text: r.stdout }; }
}

export async function runPowerQuery({ cwd, query, startMs, endMs, startIso, endIso }) {
  const args = { query };

  const sIso = startIso || (startMs != null ? new Date(startMs).toISOString() : null);
  const eIso = endIso || (endMs != null ? new Date(endMs).toISOString() : null);
  if (sIso && eIso) {
    // purple-mcp.powerquery expects start_datetime/end_datetime (ISO-8601)
    args.start_datetime = sIso;
    args.end_datetime = eIso;
  }

  const r = await mcporterCall({ cwd, tool: 'purple-mcp.powerquery', args, output: 'json', timeoutMs: 300000 });
  try {
    return JSON.parse(r.stdout);
  } catch {
    return { text: r.stdout, stderr: r.stderr };
  }
}

export async function listVulns({ cwd, first = 50 }) {
  // Keep consistent with listAlerts: Purple MCP may reject pagination args like `first`.
  // Prefer server-default page size.
  const r = await mcporterCall({ cwd, tool: 'purple-mcp.list_vulnerabilities', args: {}, output: 'json' });
  return JSON.parse(r.stdout);
}
