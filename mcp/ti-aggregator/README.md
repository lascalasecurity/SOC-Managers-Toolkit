TI Aggregator MCP (local)

Goal
- One local MCP server that fan-outs to multiple TI providers and returns a normalized enrichment.
- Keys stay local; outputs are consistent across sources.

Initial Providers (enabled first per your choice)
- OTX (AlienVault)
- GreyNoise (Community; no key)
- CISA KEV (public)
- abuse.ch (URLhaus/MalwareBazaar)

Optional Providers (later)
- VirusTotal (already wired separately; can be used here too)
- AbuseIPDB
- Shodan
- URLScan

Tools (v0)
- enrich_indicator(indicator, type=auto, sources=[...], maxPerSource=1)
  - Returns: normalized JSON { indicator, type, verdict, scores, evidence, rawRefs, errors?, normalizedAt }
- bulk_enrich(indicators[], type=auto, sources=[...], concurrency=4)
  - Returns: { count, results: [...], normalizedAt }
- ip_reputation(ip)
- url_report(url)
- domain_report(domain)
- file_report(hash)
- cve_report(cve)

Normalization
- verdict: malicious | suspicious | unknown | benign
- scores: per-source numerical or categorical mapped into 0-100
- evidence: list of key findings (detections, tags, relationships)

Auth / Env
- OTX_API_KEY (required)
- GREYNOISE_API_KEY (optional for Community)
- ABUSECH_API_KEY (for MalwareBazaar where required)

Transport
- stdio (local process)

Notes
- v0 calls official HTTP APIs directly with conservative rate limits.
- Caching: KEV feed is cached under ./cache.
- Artifacts (optional): set TI_AGG_WRITE_ARTIFACTS=1 to write JSON under security-lab/artifacts/ti/.
- Read-only lookups only.
