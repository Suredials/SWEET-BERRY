#!/bin/sh
set -eu
umask 077
mkdir -p /var/log/samba /srv/shares/NETLOGON /srv/shares/Backups
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
  rm -f /etc/samba/smb.conf
  samba-tool domain provision --realm=CORP.LOCAL --domain=CORP --server-role=dc \
    --dns-backend=SAMBA_INTERNAL --adminpass="$DOMAIN_PASSWORD" \
    --host-name=dc01 --host-ip="${ADVERTISE_IP}" --use-rfc2307 \
    --option='posix:eadb = /var/lib/samba/private/eadb.tdb'
  cat >> /etc/samba/smb.conf <<'EOF'

[Public]
    path = /srv/shares/NETLOGON
    read only = yes
    vfs objects = dfs_samba4 acl_xattr full_audit
    full_audit:prefix = %I|%u|%S
    full_audit:success = connect disconnect openat pread
    full_audit:failure = all
    full_audit:syslog = false
EOF
  sed -i '/\[global\]/a\    log level = 1 auth_json_audit:5@/var/log/samba/auth.json full_audit:1@/var/log/samba/files.log\n    rpc server dynamic port range = 50000-50010\n    interfaces = lo eth0\n    bind interfaces only = yes\n    dns update command = /bin/true' /etc/samba/smb.conf
  samba-tool user create analyst "$BAIT_PASSWORD"
fi
if ! grep -q 'dns update command' /etc/samba/smb.conf; then
  sed -i '/\[global\]/a\    dns update command = /bin/true' /etc/samba/smb.conf
fi
if ! grep -q 'ldap server require strong auth' /etc/samba/smb.conf; then
  sed -i '/\[global\]/a\    ldap server require strong auth = no' /etc/samba/smb.conf
fi
cat > /etc/krb5.conf <<'EOF'
[libdefaults]
    default_realm = CORP.LOCAL
    dns_lookup_kdc = false
[realms]
    CORP.LOCAL = {
        kdc = 127.0.0.1
    }
EOF
printf 'CORP.LOCAL Operations\nBackup rotation: weekdays 02:00\nContact: svc_backup\n' > /srv/shares/NETLOGON/operations.txt
chmod 755 /srv/shares /srv/shares/NETLOGON /srv/shares/Backups
chmod 644 /srv/shares/NETLOGON/operations.txt
python3 /opt/sweetberry/seed_company.py
exec samba --interactive --no-process-group
