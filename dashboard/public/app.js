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

function fmtSummary(summary) {
  if (!summary) return [];

  if (summary.kind === 'alerts') {
    const sev = summary.bySeverity || {};
    const st = summary.byStatus || {};
    return [
      ['Alerts', summary.total],
      ['NEW', st.NEW ?? 0],
      ['CRIT/HIGH', `${sev.CRITICAL ?? 0}/${sev.HIGH ?? 0}`]
    ];
  }

  if (summary.kind === 'vulns') {
    const sev = summary.bySeverity || {};
    return [
      ['Findings', summary.total],
      ['HIGH', sev.HIGH ?? 0],
      ['Exploited', summary.exploitedInTheWild ?? 0]
    ];
  }

  if (summary.kind === 'ti') {
    const byType = summary.byType || {};
    return [
      ['IOCs', summary.total],
      ['KEV', summary.kevCount ?? 0],
      ['CVEs', byType.cve ?? 0]
    ];
  }

  if (summary.kind === 'error') {
    return [['Summary', 'parse failed']];
  }

  return [];
}

function formatStamp(stamp) {
  if (!stamp) return '—';
  const s = String(stamp);
  // YYYYMMDD or YYYYMMDD-HHMM
  const m = s.match(/^(\d{4})(\d{2})(\d{2})(?:-(\d{2})(\d{2}))?$/);
  if (!m) return s;
  const [, y, mo, d, hh, mi] = m;
  const yy = y.slice(2);
  if (hh && mi) return `${mo}/${d}/${yy} ${hh}:${mi}:00`;
  return `${mo}/${d}/${yy}`;
}

function renderTiles(overview) {
  const el = $('#tiles');
  el.innerHTML = '';

  for (const a of overview.agents) {
    const latest = a.latest;
    const badgeClass = latest ? 'ok' : 'warn';
    const badgeText = latest ? 'latest' : 'no data';

    const rows = fmtSummary(latest?.summary);
    const rowsHtml = rows
      .map(([k, v]) => `<div class="kv__row"><div class="kv__k">${esc(k)}</div><div class="kv__v">${esc(v)}</div></div>`)
      .join('');

    const preview = latest?.preview ? `<div class="tile__preview">${esc(latest.preview)}${latest.preview.length >= 420 ? '…' : ''}</div>` : '';

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
      ${preview}
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
      <div class="agentLink__sub">${esc(a.latest?.run || 'no runs yet')}</div>
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

async function refresh() {
  try {
    setConn('ok', 'loading…');
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
