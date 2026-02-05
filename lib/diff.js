// Minimal diff helpers for daily snapshot comparisons.

export function indexBy(arr, keyFn) {
  const m = new Map();
  for (const it of arr || []) m.set(keyFn(it), it);
  return m;
}

export function pick(obj, keys) {
  const out = {};
  for (const k of keys) out[k] = obj?.[k];
  return out;
}

export function vulnKey(v) {
  // Prefer stable id; fall back to externalId/name+cve
  return v?.id || v?.externalId || `${v?.name || 'unknown'}|${v?.cve?.id || v?.cveId || ''}`;
}

export function summarizeVuln(v) {
  return {
    id: v?.id,
    externalId: v?.external_id || v?.externalId,
    severity: v?.severity,
    status: v?.status,
    name: v?.name,
    lastSeenAt: v?.last_seen_at || v?.lastSeenAt,
    detectedAt: v?.detected_at || v?.detectedAt,
    asset: v?.asset?.name || null,
    cve: v?.cve?.id || v?.cveId || null,
    epss: v?.cve?.epssScore ?? null,
    exploitedInTheWild: v?.cve?.exploitedInTheWild ?? null,
    kevAvailable: v?.cve?.kevAvailable ?? null,
    fixAvailable: v?.software?.fixVersionAvailable ?? v?.softwareFixVersionAvailable ?? null,
    software: v?.software?.name || null,
    softwareVersion: v?.software?.version || null,
    softwareFixVersion: v?.software?.fixVersion || null
  };
}

export function diffSnapshots(prev, cur) {
  const prevMap = indexBy(prev || [], (v) => v.id);
  const curMap = indexBy(cur || [], (v) => v.id);

  const added = [];
  const removed = [];
  const changed = [];

  for (const [id, v] of curMap.entries()) {
    if (!prevMap.has(id)) added.push({ id, cur: v });
    else {
      const p = prevMap.get(id);
      const fields = ['severity', 'status', 'cve', 'epss', 'exploitedInTheWild', 'kevAvailable', 'fixAvailable', 'softwareFixVersion'];
      const deltas = {};
      for (const f of fields) {
        if ((p?.[f] ?? null) !== (v?.[f] ?? null)) deltas[f] = { from: p?.[f] ?? null, to: v?.[f] ?? null };
      }
      if (Object.keys(deltas).length) changed.push({ id, deltas, prev: p, cur: v });
    }
  }
  for (const [id, v] of prevMap.entries()) {
    if (!curMap.has(id)) removed.push({ id, prev: v });
  }

  return { added, removed, changed };
}
