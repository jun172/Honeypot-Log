#!/usr/bin/env sh
set -eu

# ポート番号（Cloud Run では PORT=8080 が注入され、未設定時は 8080 にフォールバック）
PORT="${PORT:-8080}"

# 必要に応じて環境変数のデフォルト設定や事前チェックを行う（BigQuery は使わない想定）
export PYTHONUNBUFFERED="${PYTHONUNBUFFERED:-1}"

# 起動前にアプリモジュールのインポート可否を検証したい場合は以下を有効化（原因切り分け用）
# python -c "import main; print('main imported successfully')"

# exec を使うことで SIGTERM 等を uvicorn プロセスへ直接渡し、グレースフルな停止・再起動をしやすくする
exec uvicorn main:app --host 0.0.0.0 --port "${PORT}"