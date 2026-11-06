#!/usr/bin/env bash
# 1cyber Comply installer (Ubuntu/Debian with Docker already installed)
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo "[!] Docker is not installed. See: https://docs.docker.com/engine/install/ubuntu/"
  exit 1
fi

if [ ! -f .env ]; then
  cp .env.example .env
  chmod 600 .env
  echo "[+] Created .env from .env.example. Fill in your Wazuh/OPNsense credentials in .env."
fi

docker compose up -d --build
echo "[+] 1cyber Comply is running: http://127.0.0.1:8080"
