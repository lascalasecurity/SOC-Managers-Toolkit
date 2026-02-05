const sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0, UNKNOWN: -1 };

export function rankSeverity(sev) {
  const k = String(sev || 'UNKNOWN').toUpperCase();
  return sevRank[k] ?? -1;
}

export function scoreAlert({ alert, tiFindings = [] }) {
  // v0 heuristic: base on severity + TI verdicts.
  let score = 0;
  score += (rankSeverity(alert.severity) + 1) * 20; // CRITICAL ~100

  for (const f of tiFindings) {
    if (!f) continue;
    const v = f.verdict;
    if (v === 'malicious') score += 15;
    if (v === 'suspicious') score += 7;
  }

  // Clamp 0-100
  score = Math.max(0, Math.min(100, score));
  return score;
}
