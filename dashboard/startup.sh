#!/usr/bin/env sh
set -eu

export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1

RAW_PORT="${PORT:-8080}"
case "$RAW_PORT" in
  ''|*[!0-9]*)
    echo "[startup][ERROR] Invalid PORT='$RAW_PORT'" >&2
    exit 1
    ;;
  *)
    if [ "$RAW_PORT" -lt 1 ] || [ "$RAW_PORT" -gt 65535 ]; then
      echo "[startup][ERROR] Out-of-range PORT='$RAW_PORT'" >&2
      exit 1
    fi
    PORT="$RAW_PORT"
    ;;
esac
export PORT

cd /app
export PYTHONPATH="/app"

if [ ! -f "/app/main.py" ]; then
  echo "[startup][ERROR] /app/main.py not found" >&2
  exit 1
fi

# main:app のインポート可否のみ事前確認（詳細情報は内部ログに留める）
python3 - <<'PY'
import importlib
import sys

try:
    mod = importlib.import_module("main")
    if not hasattr(mod, "app"):
        sys.exit(1)
except Exception as exc:
    print(f"[startup][ERROR] Import failed: {type(exc).__name__}: {exc}", file=sys.stderr)
    sys.exit(1)
PY

exec uvicorn main:app \
  --host 0.0.0.0 \
  --port "${PORT}" \
  --workers 1 \
  --no-server-header \
  --proxy-headers \
  --forwarded-allow-ips="*" \
  --timeout-keep-alive 5 \
  --log-level warning