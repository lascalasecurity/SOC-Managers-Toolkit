Tool Schemas (draft)

enrich_indicator
- inputs:
  - indicator: string (required)
  - type: enum [auto, ip, domain, url, hash, email, cve] (default: auto)
  - sources: array[string] (subset of [virustotal, otx, greynoise, abuseipdb, shodan, urlscan, kev, abusech])
  - maxPerSource: integer (default: 1) (currently accepted but not used in v0)
- output:
  - indicator: string
  - type: string
  - verdict: enum [malicious, suspicious, unknown, benign]
  - scores: object { virustotal?: int, otx?: int, greynoise?: int, abusech?: int, kev?: int }
  - evidence: array[{ source, kind, value, url?, timestamp? }]
  - rawRefs: object
  - errors?: object
  - normalizedAt: string (ISO timestamp)

bulk_enrich
- inputs:
  - indicators: array[string] (required)
  - type: enum [auto, ip, domain, url, hash, email, cve] (default: auto)
  - sources: array[string]
  - concurrency: integer (1-16, default 4)
- output:
  - count: integer
  - results: array[enrich_indicator output]
  - normalizedAt: string

ip_reputation
- inputs: { ip: string }
- output: { verdict, scores, evidence, rawRefs }

url_report
- inputs: { url: string }
- output: { verdict, scores, evidence, rawRefs }

domain_report
- inputs: { domain: string }
- output: { verdict, scores, evidence, rawRefs }

file_report
- inputs: { hash: string }
- output: { verdict, scores, evidence, rawRefs }

cve_report
- inputs: { cve: string }
- output: { knownExploited: boolean, references: array, evidence, rawRefs }
