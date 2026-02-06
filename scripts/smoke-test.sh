#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -f mcp/.env.local ]]; then
  echo "Missing mcp/.env.local. Copy from mcp/.env.local.example and fill in keys." >&2
  exit 2
fi

set -a
# shellcheck disable=SC1091
source mcp/.env.local
set +a

echo "== MCPorter servers =="
npx -y mcporter --config config/mcporter.json list

echo "== MCPorter tools (brief) =="
npx -y mcporter --config config/mcporter.json list-tools | head -n 80

echo "== Purple MCP sanity (list_alerts first=1) =="
npx -y mcporter --config config/mcporter.json call purple-mcp.list_alerts first=1 | head -n 40

echo "== TI Aggregator feed snapshot sanity =="
npx -y mcporter --config config/mcporter.json call ti-aggregator.fetch_feed_snapshot sources=kev sources=otx limit=5 days=7 | head -n 80

echo "== Collectors =="
node agents/security-analyst/runner.js --mode collect
node agents/vuln-manager/runner.js --mode collect
node agents/ti-analyst/runner.js --mode collect --limit 25

echo "OK"
