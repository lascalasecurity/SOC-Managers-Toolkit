MCP Configuration Template

Provide these details for each MCP server you add.

Purple MCP (SentinelOne)
- Name: purple-mcp
- Transport: stdio via uvx (recommended)
- Env: PURPLEMCP_CONSOLE_BASE_URL, PURPLEMCP_CONSOLE_TOKEN
- Tools: purple_ai, powerquery, alerts, vulnerabilities, misconfigurations, inventory (read-only)

VirusTotal MCP
- Name: virustotal
- Transport: stdio via npx @burtthecoder/mcp-virustotal
- Env: VIRUSTOTAL_API_KEY
- Tools: get_domain_report, get_url_report, get_ip_report, get_file_report, relationship tools

CISA KEV MCP (public feed)
- Name: cisa-kev
- Transport: stdio or http (provider-dependent)
- Env: none (unless provider enforces a key)
- Tools (expected): get_cve, list_known_exploited, search_by_vendor, search_by_product

Common Fields
- Tools list: names, descriptions, input/output schema
- Resources: any resource types exposed
- Auth:
  - Method: Bearer token | API key | mTLS | OAuth client creds
  - Token/key value: (store via environment variable; do not commit secrets)
  - Header name (if non-standard)
- Rate limits: per-minute/hour caps
- Allowed operations: read-only vs read/write
- Target scopes: org/site/project/tenant identifiers
- Notes: version, change log URL

Create servers.local.json based on servers.example.json and set env vars in .env.local.
