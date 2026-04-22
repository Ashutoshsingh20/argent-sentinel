#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

PYTHON_BIN="/Users/ashutoshsingh/Desktop/model/.venv/bin/python"

if [ ! -x "$PYTHON_BIN" ]; then
  echo "Missing virtualenv python at $PYTHON_BIN"
  exit 1
fi

# Default to principal scope so the phase5 suite behavior matches expected cross-cloud propagation.
export STATE_KEY_SCOPE="${STATE_KEY_SCOPE:-principal}"
export APP_HOST="${APP_HOST:-0.0.0.0}"
export APP_PORT="${APP_PORT:-8000}"
export JWT_ALGORITHM="${JWT_ALGORITHM:-RS256}"
export JWT_EXEMPT_PATHS="${JWT_EXEMPT_PATHS:-/,/healthz,/metrics,/docs,/openapi.json,/model-info,/dashboard/summary,/dashboard/entities,/ingest,/ingest-batch,/intelligence/status,/intelligence/suggestions,/safety/status}"
if [ -z "${JWT_SECRET:-}" ] || [ "${JWT_SECRET:-}" = "change-me" ]; then
  export JWT_SECRET="argent-sentinel-local-dev-secret-2026-04-20-min-32-bytes"
fi
export CLOUD_ACTIONS_ENABLED="${CLOUD_ACTIONS_ENABLED:-1}"
export AWS_CLOUD_ACTIONS_ENABLED="${AWS_CLOUD_ACTIONS_ENABLED:-1}"
export AZURE_CLOUD_ACTIONS_ENABLED="${AZURE_CLOUD_ACTIONS_ENABLED:-1}"
export GCP_CLOUD_ACTIONS_ENABLED="${GCP_CLOUD_ACTIONS_ENABLED:-1}"
export CLOUD_ACTIONS_ALLOW_MUTATIONS="${CLOUD_ACTIONS_ALLOW_MUTATIONS:-1}"
export AUTH_ALLOW_INSECURE_DEV=1

if [ -z "${JWT_PRIVATE_KEY_PEM:-}" ] || [ -z "${JWT_PUBLIC_KEY_PEM:-}" ]; then
  if command -v openssl >/dev/null 2>&1; then
    KEY_DIR="${TMPDIR:-/tmp}/argent_sentinel_keys"
    mkdir -p "$KEY_DIR"
    PRIV_KEY="$KEY_DIR/dev_rs256_private.pem"
    PUB_KEY="$KEY_DIR/dev_rs256_public.pem"
    if [ ! -s "$PRIV_KEY" ] || [ ! -s "$PUB_KEY" ]; then
      openssl genpkey -algorithm RSA -out "$PRIV_KEY" -pkeyopt rsa_keygen_bits:2048 >/dev/null 2>&1
      openssl rsa -pubout -in "$PRIV_KEY" -out "$PUB_KEY" >/dev/null 2>&1
    fi
    export JWT_PRIVATE_KEY_PEM="$(cat "$PRIV_KEY")"
    export JWT_PUBLIC_KEY_PEM="$(cat "$PUB_KEY")"
  fi
fi

# Auto-select first free port in [APP_PORT, APP_PORT+20].
START_PORT="$APP_PORT"
END_PORT=$((START_PORT + 20))

is_port_busy() {
  port="$1"
  "$PYTHON_BIN" - "$port" <<'PY' >/dev/null 2>&1
import socket
import sys

port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind(("0.0.0.0", port))
except OSError:
    sys.exit(1)  # busy
finally:
    s.close()
sys.exit(0)  # free
PY
  # Python returns 0 when free; convert to shell-style busy check.
  if [ "$?" -eq 0 ]; then
    return 1
  fi
  return 0
}

port="$START_PORT"
while [ "$port" -le "$END_PORT" ]; do
  if ! is_port_busy "$port"; then
    APP_PORT="$port"
    export APP_PORT
    break
  fi
  port=$((port + 1))
done

echo "Starting Argent Sentinel on ${APP_HOST}:${APP_PORT}"

exec "$PYTHON_BIN" -m uvicorn app:app --host "$APP_HOST" --port "$APP_PORT"
