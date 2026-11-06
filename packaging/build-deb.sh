#!/usr/bin/env bash
# Build dist/1cyber-comply_<version>_all.deb from this repository.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(grep -oP 'APP_VERSION = "\K[^"]+' app/config.py)
PKG=1cyber-comply
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
ROOT="$STAGE/${PKG}_${VERSION}_all"
DEST="$ROOT/opt/1cyber-comply"

mkdir -p "$DEST" "$ROOT/DEBIAN" "$ROOT/usr/share/doc/$PKG" dist
cp -r app controls docker "$DEST/"
cp Dockerfile docker-compose.yml docker-compose.hostnet.yml requirements.txt .env.example install.sh README.md "$DEST/"
find "$DEST" -name '__pycache__' -prune -exec rm -rf {} +
cp LICENSE "$ROOT/usr/share/doc/$PKG/copyright"

cat > "$ROOT/DEBIAN/control" <<CONTROL
Package: $PKG
Version: $VERSION
Section: admin
Priority: optional
Architecture: all
Depends: docker.io | docker-ce, docker-compose-v2 | docker-compose-plugin
Maintainer: Ilie Lucian <264587038+ilielucianno@users.noreply.github.com>
Homepage: https://github.com/ilielucianno/1cyber-comply
Description: Open-source NIS2 compliance automation
 Collects evidence from Wazuh and OPNsense with read-only access, maps it to
 NIS2 Article 21 controls, tracks a compliance score, stores manual evidence
 and produces PDF reports. Runs as a Docker container in /opt/1cyber-comply.
CONTROL

install -m 0755 packaging/debian/postinst packaging/debian/prerm packaging/debian/postrm "$ROOT/DEBIAN/"
find "$ROOT/opt" -type d -exec chmod 0755 {} +
find "$ROOT/opt" -type f -exec chmod 0644 {} +
chmod 0755 "$DEST/install.sh" "$DEST/docker/entrypoint.sh"

dpkg-deb --root-owner-group --build "$ROOT" "dist/${PKG}_${VERSION}_all.deb" >/dev/null
echo "dist/${PKG}_${VERSION}_all.deb"
