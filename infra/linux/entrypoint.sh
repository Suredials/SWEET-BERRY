#!/bin/sh
set -eu
ssh-keygen -A
mkdir -p /srv/corp
chown analyst:analyst /srv/corp
if [ ! -f /srv/corp/README.txt ]; then
  printf 'CORP backup operations\nHost: backup01\nDomain: CORP.LOCAL\nBackup inventory is published after authentication.\n' > /srv/corp/README.txt
fi
runuser -u analyst -- python3 /opt/sweetberry/integrity.py &
exec /usr/sbin/sshd -D -e
