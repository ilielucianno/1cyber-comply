#!/usr/bin/env bash
# Start 1cyber Comply from a cloned repository (developers / manual installs).
# For servers, prefer the one-line installer: see README (get.sh).
set -euo pipefail
cd "$(dirname "$0")"

if ! docker compose version >/dev/null 2>&1; then
  echo "[!] Docker with Compose v2 is required. See: https://docs.docker.com/engine/install/"
  exit 1
fi

if [ ! -f .env ]; then
  cp .env.example .env
  chmod 600 .env
  echo "[+] Created .env from .env.example. Fill in your Wazuh/OPNsense credentials in .env."
fi

docker compose up -d --build
scheme=http
grep -q '^COMPLY_TLS=true' .env && scheme=https
echo "[+] 1cyber Comply is running: ${scheme}://127.0.0.1:8080"
