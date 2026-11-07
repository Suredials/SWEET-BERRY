#!/bin/sh
set -eu
cd /opt/sweetberry
python scripts/configure.py
python -m uvicorn app.api:from_environment --factory --host 127.0.0.1 --port 8000 &
api_pid=$!
trap 'kill "$api_pid" 2>/dev/null || true' EXIT INT TERM
python -m uvicorn dashboard.server:app --host 0.0.0.0 --port 8501
