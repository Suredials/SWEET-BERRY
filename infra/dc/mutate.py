"""Fixed domain mutations. No caller-supplied shell commands."""
import json
import os
import pathlib
import subprocess
import sys

action = sys.argv[1]
config = pathlib.Path('/etc/samba/smb.conf')
if action == 'expose_users':
    users = subprocess.check_output(['samba-tool', 'user', 'list'], text=True).splitlines()
    if 'svc_backup' not in users:
        subprocess.run(['samba-tool', 'user', 'create', 'svc_backup', os.environ['BAIT_PASSWORD'], '--description=SweetBerry isolated lab backup account'], check=True)
    subprocess.run(['samba-tool', 'user', 'setpassword', 'svc_backup', '--newpassword=' + os.environ['BAIT_PASSWORD']], check=True)
    subprocess.run(['samba-tool', 'user', 'setexpiry', 'svc_backup', '--noexpiry'], check=True)
elif action == 'expose_backup_share':
    content = config.read_text()
    if '[Backups$]' not in content:
        config.write_text(content + '\n[Backups$]\n    path = /srv/shares/Backups\n    read only = yes\n    browseable = yes\n    vfs objects = dfs_samba4 acl_xattr full_audit\n    full_audit:prefix = %I|%u|%S\n    full_audit:success = connect disconnect openat pread\n    full_audit:failure = all\n    full_audit:syslog = false\n')
    root = pathlib.Path('/srv/shares/Backups')
    (root / 'backup.ps1').write_text('# SWEETBERRY_CANARY_DECOY - inert lab backup documentation\n# Destination: backup01:/srv/corp\n')
    (root / 'inventory.csv').write_text('host,role\ndc01,domain_controller\nbackup01,linux_backup\n')
    for path in root.iterdir():
        path.chmod(0o644)
    subprocess.run(['smbcontrol', 'all', 'reload-config'], check=True)
elif action == 'expose_cloud_credential':
    path = pathlib.Path('/srv/shares/Backups/cloud_credentials.txt')
    path.write_text('AWS_ACCESS_KEY_ID=SWEETBERRY_CANARY_DECOY_NOT_VALID\nAWS_SECRET_ACCESS_KEY=SWEETBERRY_CANARY_DECOY_NOT_VALID\n')
    path.chmod(0o644)
elif action == 'expose_finance_share':
    folder = pathlib.Path('/srv/shares/Finance')
    folder.mkdir(exist_ok=True)
    folder.chmod(0o755)
    (folder / 'quarterly-report.csv').write_text('quarter,revenue,marker\nQ3,125000,SWEETBERRY_CANARY_DECOY_SYNTHETIC\n')
    (folder / 'quarterly-report.csv').chmod(0o644)
    content = config.read_text()
    if '[Finance$]' not in content:
        config.write_text(content + '\n[Finance$]\n    path = /srv/shares/Finance\n    read only = yes\n    browseable = yes\n    vfs objects = dfs_samba4 acl_xattr full_audit\n    full_audit:prefix = %I|%u|%S\n    full_audit:success = connect disconnect openat pread\n    full_audit:failure = all\n    full_audit:syslog = false\n')
    subprocess.run(['smbcontrol', 'all', 'reload-config'], check=True)
elif action == 'expose_sql_note':
    note = pathlib.Path('/srv/shares/NETLOGON/sql-operations.md')
    note.write_text('# Reporting services\nHost: SQL01\nDataset: synthetic quarterly reporting\nSWEETBERRY_CANARY_DECOY\n')
    note.chmod(0o644)
else:
    raise SystemExit('unsupported mutation')
print(json.dumps({'applied': action}))
