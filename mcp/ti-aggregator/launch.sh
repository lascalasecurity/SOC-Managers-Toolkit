#!/usr/bin/env bash
# Wrapper to launch ti-aggregator with TI keys from mcp/.env.local so
# gateway cron and other non-interactive callers get the same behavior
# as a local dev shell.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"  # security-lab/
ENV_FILE="$ROOT_DIR/mcp/.env.local"

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

cd "$ROOT_DIR"
exec node mcp/ti-aggregator/server.js
