#!/bin/sh
set -eu
cd "$(dirname "$0")"
python3 scripts/configure.py
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
fi
.venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt
if [ "${SWEETBERRY_OFFLINE:-false}" != true ]; then
  sudo -v
  sudo python3 scripts/configure.py
  sudo chown -R 999:999 runtime/cowrie
  sudo chown -R 10001:10001 runtime/portal runtime/forge runtime/cloud
  sudo chown -R 10001:10001 runtime/webedge runtime/chatbot
  sudo chown -R 1000:1000 runtime/linux
  sudo chown -R 65534:65534 runtime/canary
  sudo sh ops/network.sh
  sudo sh ops/guard.sh
  sudo docker volume create sweetberry_guard-cache >/dev/null
  if [ "${SWEETBERRY_BUILD:-false}" = true ] || ! sudo docker image inspect sweetberry-guard sweetberry-cloud sweetberry-webtrap sweetberry-chatbot >/dev/null 2>&1; then
    sudo docker compose build
  fi
  sudo sh ops/prepare-guard.sh
  sudo docker compose up -d
  sudo sh ops/guard.sh
  sudo sh ops/install-services.sh
  sudo sh ops/install-new-test.sh
  sudo sh ops/install-network-sensor.sh
else
  SWEETBERRY_LIVE=false .venv/bin/python -m uvicorn app.api:from_environment --factory --host 127.0.0.1 --port 8000 > runtime/collector/api.log 2>&1 &
  api_pid=$!
  trap 'kill "$api_pid" 2>/dev/null || true' EXIT INT TERM
  .venv/bin/python -m uvicorn dashboard.server:app --host 127.0.0.1 --port 8501
fi
