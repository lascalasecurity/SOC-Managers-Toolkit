#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${1:-$HOME/security-lab}"

echo "[secops-bootstrap] Target dir: $REPO_DIR"

if [ ! -d "$REPO_DIR/.git" ]; then
  echo "[secops-bootstrap] Cloning repo into $REPO_DIR"
  git clone https://github.com/lascalasecurity/Jarvis-secops.git "$REPO_DIR"
else
  echo "[secops-bootstrap] Repo already present at $REPO_DIR (skipping clone)"
fi

cd "$REPO_DIR"

echo "[secops-bootstrap] Installing npm dependencies"
npm install

echo "[secops-bootstrap] Ensuring MCP env skeleton exists"
mkdir -p mcp
if [ ! -f mcp/.env.local ]; then
  cat > mcp/.env.local << 'EOF'
# Jarvis-secops MCP local environment
#
# Fill these in with your own keys / URLs before running collectors or MCP-based agents.
# This file is .gitignored and must NOT be committed.
#
# Example variables (see docs/SETUP.md for current list):
# OTX_API_KEY=
# S1_API_TOKEN=
# S1_API_URL=
EOF
  echo "[secops-bootstrap] Created mcp/.env.local template (please edit with real keys)."
else
  echo "[secops-bootstrap] mcp/.env.local already exists (leaving as-is)."
fi

echo "[secops-bootstrap] Installing dashboard systemd user service"
mkdir -p "$HOME/.config/systemd/user"
cp systemd/secops-dashboard.service "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now secops-dashboard.service

echo "[secops-bootstrap] Applying OpenClaw cron jobs (non-fatal if OpenClaw not configured yet)"
if command -v openclaw >/dev/null 2>&1; then
  openclaw cron apply --file docs/cron-jobs.json || echo "[secops-bootstrap] WARN: cron apply failed; configure OpenClaw and re-run this step."
else
  echo "[secops-bootstrap] WARN: openclaw CLI not found on PATH; skipping cron apply."
fi

echo
echo "[secops-bootstrap] Done. Next steps:"
echo "1) Edit $REPO_DIR/mcp/.env.local with your real API keys and URLs."
echo "2) Verify dashboard: curl -sSf http://127.0.0.1:18888/api/health || echo 'dashboard not up'."
echo "3) If OpenClaw is installed: run 'openclaw cron list' and confirm security-lab jobs are present."
