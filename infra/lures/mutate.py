"""Fixed writes inside each target's own data volume."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path('/srv/data')
MARKER = 'SWEETBERRY_CANARY_DECOY'
CONTENT = {
    'expose_it_runbook': ('it-runbook.md', '# IT Operations\nBackup server: backup01\nInventory: /srv/corp/Backups/inventory.csv\nRepository: backup-scripts\n'),
    'expose_repository_notes': ('migration-notes.md', '# Cloud migration\nBuild host: BUILD01\nService identity: svc_backup\nNext milestone: publish cloud-map.json\n'),
    'expose_cloud_map': ('cloud-map.json', json.dumps({'environment': 'lab', 'bucket': 'corp-backups', 'inventory': 'inventory.csv', 'marker': MARKER}, indent=2)),
    'expose_cloud_inventory': ('inventory.csv', 'object,classification\nbackup-index.json,internal\ncloud_credentials.txt,canary\n'),
    'expose_cloud_credential': ('cloud_credentials.txt', 'AWS_ACCESS_KEY_ID=SWEETBERRY_CANARY_DECOY_NOT_VALID\nAWS_SECRET_ACCESS_KEY=SWEETBERRY_CANARY_DECOY_NOT_VALID\n'),
    'expose_finance_share': ('finance-handover.md', '# Finance handover\nQuarterly reports: Finance$\nReporting host: SQL01\nDataset: synthetic lab records\n'),
}


def apply(action):
    if action not in CONTENT:
        raise ValueError('Unsupported lure mutation')
    name, content = CONTENT[action]
    role = os.getenv('LURE_ROLE', 'portal')
    folder = ROOT / ('work' if role == 'forge' else 'objects' if role == 'cloud' else 'documents')
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(content + '\n' + ('' if name.endswith(('.json', '.csv')) else MARKER + '\n'))
    if role == 'forge':
        subprocess.run(['git', '-C', str(folder), 'add', '.'], check=True, capture_output=True)
        changed = subprocess.run(['git', '-C', str(folder), 'diff', '--cached', '--quiet']).returncode
        if changed:
            subprocess.run(['git', '-C', str(folder), 'commit', '-m', 'Publish operations documentation'], check=True, capture_output=True)
            subprocess.run(['git', '-C', str(folder), 'push', str(ROOT / 'repos/backup-scripts.git'), 'HEAD:main'], check=True, capture_output=True)
    print(json.dumps({'action': action, 'role': role, 'artifact': name}))


if __name__ == '__main__':
    apply(sys.argv[1])
