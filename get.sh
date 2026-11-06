#!/usr/bin/env bash
# 1cyber Comply - one-line installer and upgrader for Ubuntu / Debian.
#
#   curl -fsSL https://raw.githubusercontent.com/ilielucianno/1cyber-comply/main/get.sh | sudo bash
#
# Read it before running it: it is short on purpose.
#  - installs Docker from your distribution's repositories if it is missing (asks first)
#  - downloads 1cyber Comply into /opt/1cyber-comply
#  - creates /opt/1cyber-comply/.env on first install (HTTPS enabled), never overwrites it
#  - builds and starts the container; running it again upgrades in place, keeping data
#
# Options (environment variables):
#   COMPLY_VERSION=v1.0.0   install a specific release tag (default: main)
#   COMPLY_DIR=/opt/...      install directory (default: /opt/1cyber-comply)
#   COMPLY_YES=1             do not ask questions (non-interactive install)
set -euo pipefail

REPO="https://github.com/ilielucianno/1cyber-comply.git"
REF="${COMPLY_VERSION:-main}"
DIR="${COMPLY_DIR:-/opt/1cyber-comply}"

info()  { printf '\033[1;34m[+]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
fail()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

confirm() {
  [ "${COMPLY_YES:-0}" = "1" ] && return 0
  # stdin may be the script itself (curl | bash): read the answer from the terminal
  [ -r /dev/tty ] || fail "Cannot ask for confirmation; re-run with COMPLY_YES=1"
  printf '%s [y/N] ' "$1" > /dev/tty
  read -r answer < /dev/tty
  [[ "$answer" =~ ^[Yy]$ ]]
}

[ "$(id -u)" -eq 0 ] || fail "Run as root, e.g.: curl -fsSL .../get.sh | sudo bash"
[ -r /etc/os-release ] || fail "Unsupported system: /etc/os-release not found"
# Read os-release in a subshell so its variables (VERSION, NAME, ...) cannot clash with ours
os_id=$(. /etc/os-release; echo "${ID:-}")
os_like=$(. /etc/os-release; echo "${ID_LIKE:-}")
os_name=$(. /etc/os-release; echo "${PRETTY_NAME:-unknown}")
case "$os_id:$os_like" in
  ubuntu:*|debian:*|*:*debian*|*:*ubuntu*) ;;
  *) fail "Supported: Ubuntu and Debian. Detected: $os_name" ;;
esac
info "System: $os_name"

# --- dependencies -------------------------------------------------------------
missing=()
command -v git >/dev/null 2>&1 || missing+=(git)
command -v docker >/dev/null 2>&1 || missing+=(docker.io)
if command -v docker >/dev/null 2>&1 && ! docker compose version >/dev/null 2>&1; then
  missing+=(compose)
elif ! command -v docker >/dev/null 2>&1; then
  missing+=(compose)
fi

if [ ${#missing[@]} -gt 0 ]; then
  pkgs=()
  for m in "${missing[@]}"; do
    if [ "$m" = "compose" ]; then
      if apt-cache show docker-compose-v2 >/dev/null 2>&1; then pkgs+=(docker-compose-v2)
      elif apt-cache show docker-compose-plugin >/dev/null 2>&1; then pkgs+=(docker-compose-plugin)
      else fail "No Docker Compose v2 package found. Install Docker Engine: https://docs.docker.com/engine/install/"
      fi
    else
      pkgs+=("$m")
    fi
  done
  warn "Missing packages: ${pkgs[*]}"
  confirm "Install them with apt now?" || fail "Cancelled. Install the packages above and run again."
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}"
  systemctl enable --now docker >/dev/null 2>&1 || true
fi
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is not working"

# --- download / upgrade --------------------------------------------------------
if [ -d "$DIR/.git" ]; then
  info "Existing installation found in $DIR: upgrading to '$REF'"
  git -C "$DIR" fetch --quiet --depth 1 origin "$REF"
  git -C "$DIR" checkout --quiet --force FETCH_HEAD
else
  [ -e "$DIR" ] && fail "$DIR exists but is not a 1cyber Comply installation"
  info "Downloading 1cyber Comply ($REF) into $DIR"
  git clone --quiet --depth 1 --branch "$REF" "$REPO" "$DIR"
fi
cd "$DIR"

# --- configuration -------------------------------------------------------------
if [ ! -f .env ]; then
  cp .env.example .env
  sed -i 's/^COMPLY_TLS=.*/COMPLY_TLS=true/' .env
  sed -i "s/^COMPLY_TLS_HOSTNAME=.*/COMPLY_TLS_HOSTNAME=$(hostname)/" .env
  chmod 600 .env
  info "Created $DIR/.env (HTTPS enabled). Add your Wazuh / OPNsense details there."
else
  info "Keeping existing $DIR/.env"
fi

# --- start ---------------------------------------------------------------------
info "Building and starting the container (first run takes a few minutes)"
docker compose up -d --build --remove-orphans

scheme=http
grep -q '^COMPLY_TLS=true' .env && scheme=https
version=$(grep -oP 'APP_VERSION = "\K[^"]+' app/config.py || echo "?")
echo
info "1cyber Comply v${version} is running: ${scheme}://127.0.0.1:8080"
echo "    First visit: create the administrator account."
echo "    Settings:    sudo nano $DIR/.env   then   cd $DIR && sudo docker compose up -d --force-recreate"
echo "    Upgrade:     run this installer again"
echo "    Locked out:  sudo docker exec -it 1cyber-comply python -m app.cli reset-password <user>"
