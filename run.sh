#!/usr/bin/env sh
set -eu
exec uvicorn adaptive_zta.app:app \
  --host "${APP_HOST:-0.0.0.0}" \
  --port "${APP_PORT:-8000}" \
  --workers 1
