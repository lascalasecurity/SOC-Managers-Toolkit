// Strict-ish IOC extraction helpers.

export function isIPv4(s) {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(s)) return false;
  return s.split('.').every((o) => {
    const n = Number(o);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
}

export function isHash(s) {
  return /^[a-fA-F0-9]{32}$/.test(s) || /^[a-fA-F0-9]{40}$/.test(s) || /^[a-fA-F0-9]{64}$/.test(s);
}

export function isCVE(s) {
  return /^CVE-\d{4}-\d{4,7}$/i.test(s);
}

export function isUrl(s) {
  try {
    const u = new URL(s);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

export function isDomain(s) {
  // Avoid filenames and obvious non-domains.
  const lower = s.toLowerCase();
  if (lower.endsWith('.exe') || lower.endsWith('.dll') || lower.endsWith('.sys')) return false;
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(lower)) return false;
  if (lower.length > 253) return false;
  if (lower.includes('..')) return false;
  return true;
}

export function extractIOCs(text) {
  const out = [];
  if (!text) return out;

  const candidates = new Set();

  // Emails: add only the domain part; explicitly suppress local-part tokens that look domain-ish (e.g., aviv.baron@sentinelone.com)
  const emailLocals = new Set();
  for (const m of text.matchAll(/\b([A-Z0-9._%+-]+)@([A-Z0-9.-]+\.[A-Z]{2,})\b/gi)) {
    const local = String(m[1] || '').toLowerCase();
    const dom = String(m[2] || '').toLowerCase();
    if (local) emailLocals.add(local);
    if (dom) candidates.add(dom);
  }

  // URLs
  for (const m of text.matchAll(/https?:\/\/[^\s'"<>]+/gi)) candidates.add(m[0]);
  // IPs
  for (const m of text.matchAll(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g)) candidates.add(m[0]);
  // CVEs
  for (const m of text.matchAll(/\bCVE-\d{4}-\d{4,7}\b/gi)) candidates.add(m[0].toUpperCase());
  // Hashes (md5/sha1/sha256)
  for (const m of text.matchAll(/\b[a-f0-9]{32}\b/gi)) candidates.add(m[0]);
  for (const m of text.matchAll(/\b[a-f0-9]{40}\b/gi)) candidates.add(m[0]);
  for (const m of text.matchAll(/\b[a-f0-9]{64}\b/gi)) candidates.add(m[0]);
  // Domains (keep conservative)
  for (const m of text.matchAll(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi)) {
    const dom = String(m[0] || '').toLowerCase();
    if (emailLocals.has(dom)) continue; // suppress email local-part false positives
    candidates.add(dom);
  }

  for (const c of candidates) {
    if (isUrl(c)) out.push({ indicator: c, type: 'url' });
    else if (isIPv4(c)) out.push({ indicator: c, type: 'ip' });
    else if (isCVE(c)) out.push({ indicator: c, type: 'cve' });
    else if (isHash(c)) out.push({ indicator: c.toLowerCase(), type: 'hash' });
    else if (isDomain(c)) out.push({ indicator: c.toLowerCase(), type: 'domain' });
  }

  // Dedupe by type+indicator
  const seen = new Set();
  const deduped = [];
  for (const it of out) {
    const k = `${it.type}:${it.indicator}`;
    if (seen.has(k)) continue;
    seen.add(k);
    deduped.push(it);
  }
  return deduped;
}
