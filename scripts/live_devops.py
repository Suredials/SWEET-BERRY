"""Read-only portal → real Git clone → lab objects demonstration."""
import argparse
from pathlib import Path
import subprocess
import time
import requests

ROOT = Path(__file__).resolve().parents[1]


def wait_for(url):
    for attempt in range(30):
        response = requests.get(url, timeout=5)
        if response.ok:
            return response
        if response.status_code != 404:
            response.raise_for_status()
        time.sleep(.5)
    raise RuntimeError('Artifact did not appear: ' + url)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default=None)
    host = parser.parse_args().host
    portal, forge, cloud = [f'http://{host or address}:{port}' for address, port in (('172.27.66.30',8088), ('172.27.66.40',3000), ('172.27.66.50',9080))]
    directory = requests.get(portal + '/api/directory', timeout=5)
    directory.raise_for_status()
    print('DIRECTORY:', [row['username'] for row in directory.json()['employees']])
    print('RUNBOOK:', wait_for(portal + '/documents/it-runbook.md').status_code)
    repositories = requests.get(forge + '/api/repos', timeout=5)
    repositories.raise_for_status()
    print('REPOSITORY CATALOG:', repositories.json())
    print('MIGRATION NOTES:', wait_for(forge + '/api/files/migration-notes.md').status_code)
    print('CLOUD MAP:', wait_for(forge + '/api/files/cloud-map.json').json())
    destination = ROOT / 'runtime' / ('git-demo-' + str(time.time_ns()))
    destination.parent.mkdir(exist_ok=True)
    result = subprocess.run(['git', 'clone', '--depth', '1', forge + '/repos/backup-scripts.git', str(destination)], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr)
    print('REAL GIT CLONE:', sorted(file.name for file in destination.iterdir() if file.is_file()))
    response = requests.get(cloud + '/api/buckets', timeout=5)
    response.raise_for_status()
    print('LAB BUCKETS:', response.json()['buckets'])
    root = cloud + '/api/buckets/corp-backups/objects/'
    print('DYNAMIC INVENTORY:', wait_for(root + 'inventory.csv').text.strip())
    canary = wait_for(root + 'cloud_credentials.txt')
    assert 'SWEETBERRY_CANARY_DECOY' in canary.text
    print('CANARY CONFIRMED: lab-only markers; no production credentials')
    print('DevOps path complete. Git working copy retained at', destination)


if __name__ == '__main__':
    main()
