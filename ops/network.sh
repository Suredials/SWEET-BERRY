#!/bin/sh
# Public lab aliases; never replace the management address or restart the AP.
set -eu
test "$(id -u)" = 0
ready=false
for attempt in $(seq 1 30); do
  if ip -4 addr show dev wlan0 2>/dev/null | grep -q '172.27.66.1/24'; then ready=true; break; fi
  sleep 1
done
test "$ready" = true
nmcli connection modify kali-mgmt-ap ipv4.shared-dhcp-range '172.27.66.100,172.27.66.254'
for octet in 10 20 30 40 50 60 70 80; do
  ip address replace "172.27.66.$octet/32" dev wlan0
  # Published Docker ports are DNATed before INPUT. Block host daemons here.
  iptables -C INPUT -d "172.27.66.$octet" -m conntrack --ctstate NEW -j REJECT 2>/dev/null || iptables -I INPUT 1 -d "172.27.66.$octet" -m conntrack --ctstate NEW -j REJECT
done
install -d /etc/ssh/sshd_config.d
printf '%s\n' 'ListenAddress 172.27.66.1' > /etc/ssh/sshd_config.d/20-sweetberry-admin.conf
sshd -t
install -d /etc/systemd/system/ssh.service.d
cat > /etc/systemd/system/ssh.service.d/20-sweetberry-network.conf <<'EOF'
[Unit]
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0
[Service]
Restart=on-failure
RestartSec=3
EOF
systemctl daemon-reload
if systemctl is-active --quiet ssh; then systemctl reload ssh; else systemctl start ssh; fi
echo 'Management .1; lab aliases .10 .20 .30 .40 .50 .60 .70 .80. DHCP reservation saved.'
