#!/usr/bin/env bash
# Instalare 1cyber Comply (Ubuntu/Debian cu Docker deja instalat)
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo "[!] Docker nu este instalat. Instaleaza: https://docs.docker.com/engine/install/ubuntu/"
  exit 1
fi

if [ ! -f .env ]; then
  cp .env.example .env
  chmod 600 .env
  echo "[+] Am creat .env din .env.example. Completeaza credentialele Wazuh/OPNsense in .env."
fi

docker compose up -d --build
echo "[+] 1cyber Comply ruleaza: http://127.0.0.1:8080"
