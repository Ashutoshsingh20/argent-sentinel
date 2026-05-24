FROM python:3.11-slim

WORKDIR /app

# System deps needed for build (numpy, torch wheels, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl sqlite3 && rm -rf /var/lib/apt/lists/*

# Python deps — install first for Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY . .

# Per-org data directories (mounted as volumes at runtime)
RUN mkdir -p /app/data /app/models /app/policies

ENV APP_HOST=0.0.0.0
ENV APP_PORT=8000
ENV TENANT_ISOLATION=1
ENV PYTHONPATH=/app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl -f http://localhost:${APP_PORT}/healthz || exit 1

CMD ["sh", "run.sh"]
