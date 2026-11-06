FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    COMPLY_DATA_DIR=/data

WORKDIR /app

# DejaVu fonts: PDF reports render diacritics (ă, ș, ț, Greek, ...) correctly
RUN apt-get update && apt-get install -y --no-install-recommends fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY controls ./controls

# Run as an unprivileged user
RUN useradd --create-home --uid 1000 comply && mkdir -p /data && chown comply:comply /data
USER comply

# Listen address and port. Host-network mode sets COMPLY_HOST=127.0.0.1
ENV COMPLY_HOST=0.0.0.0 \
    COMPLY_PORT=8080

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import os,urllib.request;urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"COMPLY_PORT\",\"8080\")}/health')"

CMD ["sh", "-c", "exec uvicorn app.main:app --host \"$COMPLY_HOST\" --port \"$COMPLY_PORT\""]
