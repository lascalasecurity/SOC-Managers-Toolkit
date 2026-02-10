const $ = (sel) => document.querySelector(sel);

const state = {
  overview: null,
  selectedAgent: null,
  selectedRunPath: null
};

function setConn(status, text) {
  const pill = $('#connPill');
  pill.classList.remove('ok', 'bad');
  if (status === 'ok') pill.classList.add('ok');
  if (status === 'bad') pill.classList.add('bad');
  pill.textContent = text;
}

async function api(path) {
  const res = await fetch(path, { cache: 'no-store' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

function esc(s) {
  return String(s).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}

function fmtSummary(summary, weekly, agentId) {
  // Security Analyst: alert posture + activity
  if (agentId === 'security-analyst') {
    const rows = [];
    if (summary && summary.kind === 'alerts') {
      const sev = summary.bySeverity || {};
      rows.push(['Alerts (latest)', summary.total]);
      rows.push(['HIGH/CRITICAL & STILL OPEN', summary.openHighCrit ?? 0]);
      rows.push(['New alerts (24h)', summary.new24h ?? 0]);
    }
    if (weekly?.alerts7d != null) rows.push(['Distinct alerts (7d)', weekly.alerts7d]);
    if (weekly?.runs7d != null) rows.push(['Runs (7d)', weekly.runs7d]);
    return rows;
  }

  // TI Digest: IOC volume + KEV density
  if (agentId === 'ti-digest' && summary && summary.kind === 'ti') {
    const byType = summary.byType || {};
    return [
      ['IOCs (today)', summary.total],
      ['KEV CVEs', summary.kevCount ?? 0],
      ['Infra IOCs', (byType.domain ?? 0) + (byType.ip ?? 0) + (byType.url ?? 0)]
    ];
  }

  // Vulnerability Manager: risk posture snapshot
  if (agentId === 'vuln-manager' && summary && summary.kind === 'vulns') {
    const sev = summary.bySeverity || {};
    const highCrit = (sev.CRITICAL ?? 0) + (sev.HIGH ?? 0);
    return [
      ['Findings (latest)', summary.total],
      ['HIGH/CRIT', highCrit],
      ['Exploited (KEV)', summary.exploitedInTheWild ?? 0]
    ];
  }

  // SOC Manager: meta health + QA corrections
  if (agentId === 'soc-manager' && weekly) {
    return [
      ['Daily reports (7d)', weekly.dailyReports7d ?? 0],
      ['Weekly reports (7d)', weekly.weeklyReports7d ?? 0],
      ['QA issues (7d)', weekly.qaIssues7d ?? 0]
    ];
  }

  // Hunts (Threat Hunter / Proactive Hunter): keep weekly hunt stats.
  if ((agentId === 'threat-hunter' || agentId === 'proactive-hunter') && weekly) {
    const hunts = weekly.hunts7d ?? weekly.runs7d ?? 0;
    return [
      ['Runs (7d)', weekly.runs7d ?? 0],
      ['Hunts (7d)', hunts]
    ];
  }

  // Other agents: no per-tile summary rows yet (will be replaced with cleaner stats).
  return [];
}

function formatStamp(stamp) {
  if (!stamp) return '—';
  const s = String(stamp);
  // YYYYMMDD or YYYYMMDD-HHMM
  const m = s.match(/^(\d{4})(\d{2})(\d{2})(?:-(\d{2})(\d{2}))?$/);
  if (!m) return s;
  const [, y, mo, d, hh, mi] = m;
  // Display as MM/DD/YYYY HH:MM (no seconds) for clarity in the UI
  if (hh && mi) return `${mo}/${d}/${y} ${hh}:${mi}`;
  return `${mo}/${d}/${y}`;
}

function renderTiles(overview) {
  const el = $('#tiles');
  el.innerHTML = '';

  for (const a of overview.agents) {
    const latest = a.latest;
    const badgeClass = latest ? 'ok' : 'warn';
    const badgeText = latest ? 'latest' : 'no data';

    const rows = fmtSummary(latest?.summary, latest?.weekly, a.agent);
    const rowsHtml = rows
      .map(([k, v]) => `<div class="kv__row"><div class="kv__k">${esc(k)}</div><div class="kv__v">${esc(v)}</div></div>`)
      .join('');

    const tile = document.createElement('div');
    tile.className = 'tile';
    tile.innerHTML = `
      <div class="tile__top">
        <div>
          <div class="tile__name">${esc(a.agentName)}</div>
          <div class="tile__sub">${esc(a.agent)}</div>
        </div>
        <div class="badge ${badgeClass}">${badgeText}</div>
      </div>
      <div class="kv">
        <div class="kv__row"><div class="kv__k">Latest run</div><div class="kv__v">${esc(formatStamp(latest?.ts || latest?.run || ''))}</div></div>
        ${rowsHtml}
      </div>
    `;

    tile.addEventListener('click', async () => {
      state.selectedAgent = a.agent;
      await loadRuns(a.agent);
      if (latest?.path) {
        await openRun(latest.path, a.agentName);
      }
    });

    el.appendChild(tile);
  }
}

function renderAgentsList(overview) {
  const el = $('#agentsList');
  el.innerHTML = '';

  for (const a of overview.agents) {
    const row = document.createElement('div');
    row.className = 'agentLink';
    row.innerHTML = `
      <div style="font-weight:700">${esc(a.agentName)}</div>
    `;
    row.addEventListener('click', async () => {
      state.selectedAgent = a.agent;
      await loadRuns(a.agent);
    });
    el.appendChild(row);
  }
}

async function loadRuns(agent) {
  const data = await api(`/api/agent/${encodeURIComponent(agent)}/runs`);
  const el = $('#runsList');
  el.innerHTML = '';

  for (const r of data.runs.slice(0, 40)) {
    const item = document.createElement('div');
    item.className = 'runItem';
    item.innerHTML = `
      <div class="runItem__name">${esc(r.run)}</div>
      <div class="runItem__ts">${esc(formatStamp(r.ts || r.run || ''))}</div>
    `;
    item.addEventListener('click', async () => {
      await openRun(r.path, data.agentName);
    });
    el.appendChild(item);
  }
}

async function openRun(runPath, agentName) {
  state.selectedRunPath = runPath;

  const detail = $('#detailPanel');
  detail.style.display = 'block';

  $('#detailTitle').textContent = `${agentName} — ${runPath}`;
  $('#detailMeta').textContent = `path=${runPath}`;

  const r = await api(`/api/run?path=${encodeURIComponent(runPath)}`);
  const filesEl = $('#detailFiles');
  filesEl.innerHTML = '';

  const files = r.files || [];
  const preferred = ['report.md', 'digest.md', 'collector.log.txt', 'alerts.json', 'vulnerabilities.raw.json', 'ti_iocs.json'];
  files.sort((a, b) => {
    const ai = preferred.indexOf(a);
    const bi = preferred.indexOf(b);
    if (ai !== -1 || bi !== -1) {
      return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi);
    }
    return a.localeCompare(b);
  });

  for (const f of files) {
    const btn = document.createElement('div');
    btn.className = 'fileBtn';
    btn.textContent = f;
    btn.addEventListener('click', async () => {
      await openFile(`${runPath}/${f}`);
    });
    filesEl.appendChild(btn);
  }

  // auto-open first preferred file if present
  const auto = preferred.find((p) => files.includes(p)) || files[0];
  if (auto) await openFile(`${runPath}/${auto}`);
}

async function openFile(filePath) {
  const prev = $('#detailPreview');
  prev.innerHTML = '<div class="muted">loading…</div>';

  const a = await api(`/api/artifact?path=${encodeURIComponent(filePath)}`);
  if (!a.ok) {
    prev.innerHTML = `<div class="muted">error loading artifact</div>`;
    return;
  }

  if (a.html) {
    prev.innerHTML = a.html;
    return;
  }

  if (a.data) {
    prev.innerHTML = `<pre>${esc(JSON.stringify(a.data, null, 2))}</pre>`;
    return;
  }

  prev.innerHTML = `<pre>${esc(a.text || '')}</pre>`;
}

async function loadSocDaily() {
  try {
    const d = await api('/api/soc-daily');
    $('#socDailyMeta').textContent = `Day: ${formatStamp(d.day)} — ${d.file}`;
    $('#socDailyContent').innerHTML = d.html;
  } catch (e) {
    $('#socDailyMeta').textContent = 'No daily overview yet';
    $('#socDailyContent').innerHTML = '<div class="muted">Waiting for first daily SOC Manager run…</div>';
  }
}

async function refresh() {
  try {
    setConn('ok', 'loading…');
    await loadSocDaily();
    const overview = await api('/api/overview');
    state.overview = overview;
    renderTiles(overview);
    renderAgentsList(overview);
    setConn('ok', 'live');
  } catch (e) {
    setConn('bad', `offline (${e.message})`);
  }
}

function startSSE() {
  const es = new EventSource('/api/events');

  es.addEventListener('hello', () => {
    setConn('ok', 'live');
  });

  // Any FS change triggers a refresh, but we debounce a bit.
  let t = null;
  es.addEventListener('fs', () => {
    clearTimeout(t);
    t = setTimeout(() => refresh().catch(() => {}), 350);
  });

  es.onerror = () => {
    setConn('bad', 'reconnecting…');
  };
}

$('#refreshBtn').addEventListener('click', () => refresh());

refresh().then(() => startSSE());
