#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cat > /etc/systemd/system/sweetberry-new-test.service <<EOF
[Unit]
Description=SweetBerry archive capture and start a new test
After=sweetberry-infra.service
[Service]
Type=oneshot
WorkingDirectory=$root
ExecStartPre=/bin/sleep 1
ExecStart=$root/.venv/bin/python $root/ops/new_test.py
UMask=0077
TimeoutStartSec=150
EOF
systemctl daemon-reload
