#!/bin/sh
# Project-scoped filtering. Run again after restarting Docker.
set -eu
iptables -t nat -D PREROUTING -s 172.30.67.80 -j SWEETBERRY-PIVOT 2>/dev/null || true
iptables -t nat -F SWEETBERRY-PIVOT 2>/dev/null || true
iptables -t nat -X SWEETBERRY-PIVOT 2>/dev/null || true
iptables -N SWEETBERRY-EGRESS 2>/dev/null || true
iptables -F SWEETBERRY-EGRESS
iptables -A SWEETBERRY-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -A SWEETBERRY-EGRESS -s 172.30.67.0/24 -d 172.30.67.53 -p udp --dport 53 -j ACCEPT
iptables -A SWEETBERRY-EGRESS -s 172.30.67.0/24 -d 172.30.67.53 -p tcp --dport 53 -j ACCEPT
# Fixed application gateways and the deliberately bounded post-access path.
for route in '172.30.67.42 172.30.67.40 3000' '172.30.67.50 172.30.67.51 5000' '172.30.67.81 172.30.67.80 8080' '172.30.67.80 172.30.67.42 8080' '172.30.67.80 172.30.67.50 8080'; do
  set -- $route
  iptables -A SWEETBERRY-EGRESS -s "$1" -d "$2" -p tcp --dport "$3" -j ACCEPT
done
iptables -A SWEETBERRY-EGRESS -s 172.30.67.0/24 -m conntrack --ctstate NEW -j REJECT
iptables -A SWEETBERRY-EGRESS -j RETURN
iptables -C DOCKER-USER -j SWEETBERRY-EGRESS 2>/dev/null || iptables -I DOCKER-USER 1 -j SWEETBERRY-EGRESS
for subnet in 172.30.67.0/24 172.30.66.0/24; do
  iptables -C INPUT -s "$subnet" -m conntrack --ctstate NEW -j REJECT 2>/dev/null || iptables -I INPUT 1 -s "$subnet" -m conntrack --ctstate NEW -j REJECT
done
iptables -C INPUT -s 172.30.67.70 -d 172.30.67.1 -p tcp --dport 8001 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -s 172.30.67.70 -d 172.30.67.1 -p tcp --dport 8001 -j ACCEPT
if command -v nft >/dev/null && nft list chain ip nm-shared-wlan0 nat_postrouting >/dev/null 2>&1; then
  if ! nft list chain ip nm-shared-wlan0 nat_postrouting | grep -q 'sweetberry-preserve-source'; then
    nft insert rule ip nm-shared-wlan0 nat_postrouting ip daddr 172.30.67.0/24 return comment sweetberry-preserve-source
  fi
fi
echo 'SweetBerry egress and host-access guard installed'
