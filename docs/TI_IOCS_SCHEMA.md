# TI IOC Feed Schema (v0)

This repo produces a deterministic, machine-readable TI IOC feed for other agents (especially the Proactive Threat Hunter).

The TI Analyst **reasoning agent** decides what to include and why.
The `agents/ti-analyst/runner.js` script is a **collector/helper** that writes the feed in a stable format.

## Output file

- `artifacts/cron/ti-digest/<YYYYMMDD>/ti_iocs.json`

## Top-level shape

```json
{
  "generatedAt": "2026-02-06T14:00:00.000Z",
  "schema": "security-lab:ti-iocs:v0",
  "input": { "path": "config/ti-iocs.seed.json", "count": 12 },
  "count": 12,
  "iocs": [ ... ]
}
```

## IOC entry shape

```json
{
  "indicator": "CVE-2024-XXXX",
  "type": "cve",
  "context": "why this matters / campaign / family",
  "tags": ["ransomware", "initial-access"],
  "confidence": "high|medium|low|unknown",
  "relevance": "high|medium|low|unknown",
  "sources": ["otx", "virustotal"],
  "firstSeen": "2026-02-06T00:00:00Z",
  "ttlDays": 14
}
```

### Required
- `indicator` (string)
- `type` (string; can be `auto`)

### Notes
- `context`, `tags`, `confidence`, and `relevance` are meant to be set by the **reasoning** TI Analyst.
- Collector mode may output `unknown` where judgment is required.

## Seed input (optional)

The collector can read from:
- `config/ti-iocs.seed.json` (default)

Supported formats:

1) Array of strings/objects:
```json
[
  "cobaltstrike.com",
  {"indicator": "CVE-2024-XXXX", "type": "cve"}
]
```

2) Object wrapper:
```json
{ "iocs": [ {"indicator": "1.2.3.4", "type": "ip"} ] }
```
