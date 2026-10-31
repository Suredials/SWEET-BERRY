"""Verify a harmless lab file write is observed without inventing attribution."""
import time
import paramiko
import requests

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('172.27.66.20', port=22, username='analyst', password='SWEETBERRY_CANARY_DECOY_LabOnly!', timeout=5, allow_agent=False, look_for_keys=False)
_, output, errors = client.exec_command("printf '%s\\n' 'SWEETBERRY_CANARY_DECOY status=ok' > /srv/corp/demo-status.txt", timeout=5)
assert output.channel.recv_exit_status() == 0, errors.read().decode()
client.close()
for attempt in range(30):
    document = requests.get('http://172.27.66.1:8501/api/data', timeout=8).json()
    changes = [row for row in document['environment'].get('file_changes', []) if row['target'] == '/srv/corp/demo-status.txt']
    if changes:
        assert changes[-1]['metadata']['origin'] == 'unattributed'
        print('FILESYSTEM_CHANGE_CONFIRMED', changes[-1]['metadata']['change'], changes[-1]['target'])
        break
    time.sleep(.5)
else:
    raise RuntimeError('File change not observed')
