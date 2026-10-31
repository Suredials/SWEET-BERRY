#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
owner=$(stat -c %U "$root")
cat > /etc/systemd/system/sweetberry-infra.service <<EOF
[Unit]
Description=SweetBerry guarded containers
Requires=docker.service
After=docker.service network-online.target
PartOf=docker.service
[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$root
ExecStartPre=/bin/sh $root/ops/network.sh
ExecStartPre=/bin/sh $root/ops/guard.sh
ExecStart=/usr/bin/docker compose up -d
ExecStartPost=/bin/sh $root/ops/guard.sh
ExecStartPost=$root/.venv/bin/python $root/ops/seed-services.py
ExecStop=/usr/bin/docker compose stop
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/sweetberry-api.service <<EOF
[Unit]
Description=SweetBerry collector and control plane
After=sweetberry-infra.service network-online.target
Requires=sweetberry-infra.service
[Service]
WorkingDirectory=$root
EnvironmentFile=$root/.env
Environment=SWEETBERRY_LIVE=true
ExecStart=$root/.venv/bin/python -m uvicorn app.api:from_environment --factory --host 127.0.0.1 --port 8000
Restart=on-failure
UMask=0077
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/sweetberry-dashboard.service <<EOF
[Unit]
Description=SweetBerry dashboard
After=sweetberry-api.service
[Service]
User=$owner
WorkingDirectory=$root
EnvironmentFile=$root/.env
ExecStart=$root/.venv/bin/python -m uvicorn dashboard.server:app --host 172.27.66.1 --port 8501
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/sweetberry-chat-broker.service <<EOF
[Unit]
Description=SweetBerry private guarded chatbot inference
After=sweetberry-infra.service
Requires=sweetberry-infra.service
[Service]
WorkingDirectory=$root
EnvironmentFile=$root/.env
ExecStart=$root/.venv/bin/python -m uvicorn app.chat_broker:app --host 172.30.67.1 --port 8001
Restart=on-failure
UMask=0077
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now sweetberry-infra.service
systemctl enable --now sweetberry-api.service
systemctl restart sweetberry-api.service
systemctl enable --now sweetberry-chat-broker.service
systemctl restart sweetberry-chat-broker.service
if [ -f "$root/dashboard/server.py" ]; then
  systemctl enable --now sweetberry-dashboard.service
  systemctl restart sweetberry-dashboard.service
fi
echo 'SweetBerry dashboard: http://172.27.66.1:8501'
