#!/bin/sh
# Starts 1cyber Comply. With COMPLY_TLS=true it serves HTTPS, creating a
# self-signed certificate on first start unless one is provided in /data/tls.
set -e
if [ "${COMPLY_TLS:-false}" = "true" ]; then
  CERT=/data/tls/cert.pem
  KEY=/data/tls/key.pem
  if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    mkdir -p /data/tls
    openssl req -x509 -newkey rsa:3072 -nodes -days 825 \
      -subj "/CN=${COMPLY_TLS_HOSTNAME:-1cyber-comply}" \
      -addext "subjectAltName=DNS:${COMPLY_TLS_HOSTNAME:-1cyber-comply},DNS:localhost,IP:127.0.0.1" \
      -keyout "$KEY" -out "$CERT" 2>/dev/null
    chmod 600 "$KEY"
    echo "Created a self-signed certificate in /data/tls (replace cert.pem/key.pem with your own if needed)."
  fi
  exec uvicorn app.main:app --host "$COMPLY_HOST" --port "$COMPLY_PORT" \
       --ssl-certfile "$CERT" --ssl-keyfile "$KEY" --proxy-headers
fi
exec uvicorn app.main:app --host "$COMPLY_HOST" --port "$COMPLY_PORT" --proxy-headers
