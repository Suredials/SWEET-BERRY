#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ "$(id -u)" -ne 0 ]; then
  exec sudo sh "$PWD/reset_demo.sh"
fi
root=$(pwd -P)
case "$root" in /home/suredials/sweetberry) ;; *) echo 'Reset restricted to /home/suredials/sweetberry'; exit 1 ;; esac
systemctl stop sweetberry-api.service sweetberry-dashboard.service sweetberry-chat-broker.service sweetberry-network-sensor.service sweetberry-pcap.service 2>/dev/null || true
docker compose down --volumes
archive="$root/runtime/archive/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$archive"
for name in collector cowrie dc portal forge cloud linux canary telemetry network pcap webedge chatbot broker; do
  if [ -d "$root/runtime/$name" ]; then
    mv "$root/runtime/$name" "$archive/$name"
  fi
done
python3 scripts/configure.py
chown -R 999:999 runtime/cowrie
chown -R 10001:10001 runtime/portal runtime/forge runtime/cloud
chown -R 10001:10001 runtime/webedge runtime/chatbot
chown -R 1000:1000 runtime/linux
chown -R 65534:65534 runtime/canary
sh ops/network.sh
sh ops/guard.sh
docker compose up -d
sh ops/guard.sh
.venv/bin/python ops/seed-services.py
sh ops/install-network-sensor.sh
systemctl restart sweetberry-network-sensor.service sweetberry-pcap.service
ready=false
for attempt in $(seq 1 30); do
  if docker compose exec -T dc smbclient -L 127.0.0.1 -U 'CORP/analyst%SWEETBERRY_CANARY_DECOY_LabOnly!' >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 2
done
if [ "$ready" != true ]; then
  echo 'DC not ready; inspect docker compose logs dc'
  exit 1
fi
systemctl start sweetberry-api.service
systemctl start sweetberry-chat-broker.service
if [ -f dashboard/server.py ]; then systemctl start sweetberry-dashboard.service; fi
echo 'SweetBerry reset; prior telemetry archived. Initial domain and Linux restored.'
