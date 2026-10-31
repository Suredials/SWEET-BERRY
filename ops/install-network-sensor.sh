#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
python3 "$root/ops/configure-network-sensor.py"
suricata -T -c "$root/runtime/network/suricata.yaml" > "$root/runtime/network/config-test.log" 2>&1
systemctl disable --now suricata.service 2>/dev/null || true
cat > /etc/systemd/system/sweetberry-network-sensor.service <<EOF
[Unit]
Description=SweetBerry scoped Suricata IDS
After=sweetberry-infra.service
Requires=sweetberry-infra.service
[Service]
WorkingDirectory=$root
ExecStartPre=/usr/bin/python3 $root/ops/configure-network-sensor.py
ExecStart=/usr/bin/suricata --af-packet -c $root/runtime/network/suricata.yaml
Restart=on-failure
UMask=0077
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/sweetberry-pcap.service <<EOF
[Unit]
Description=SweetBerry 1GB circular laboratory packet capture
After=sweetberry-infra.service
Requires=sweetberry-infra.service
[Service]
ExecStart=/usr/bin/tcpdump -Z root -i any -nn -s 0 -C 128 -W 8 -w $root/runtime/pcap/lab.pcap -F $root/runtime/network/capture.filter
Restart=on-failure
UMask=0077
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now sweetberry-network-sensor sweetberry-pcap
