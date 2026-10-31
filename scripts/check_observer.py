"""Benign Linux operations plus a blocked connection to a documentation-only IP."""
import time
import paramiko
import requests

started = time.time()
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('172.27.66.20', port=22, username='analyst', password='SWEETBERRY_CANARY_DECOY_LabOnly!',
               timeout=10, allow_agent=False, look_for_keys=False)
shell = client.invoke_shell()
shell.send("/usr/bin/id; printf 'SWEETBERRY_CANARY_DECOY observer check\\n' > /srv/corp/observer-check.txt; /usr/bin/curl --noproxy '*' -k -m 3 https://203.0.113.55/; /usr/bin/true\n")
time.sleep(5)
while shell.recv_ready():
    shell.recv(65536)
shell.close()
client.close()
for _ in range(20):
    data = requests.get('http://172.27.66.1:8501/api/data', timeout=10).json()
    rows = [r for r in data['observer']['events'] if r['timestamp'] >= started]
    execs = [r for r in rows if r['kind'] == 'process_exec' and r['executable'] == '/usr/bin/id']
    connects = [r for r in rows if r['kind'] == 'network_connect' and r['destination'] == '203.0.113.55']
    writes = [r for r in rows if r['kind'] == 'file_write_open' and r['path'] == '/srv/corp/observer-check.txt']
    if execs and connects and writes:
        assert connects[-1]['result'] != '0', 'Unexpected successful outbound connection'
        print('PASS host-observed process execution')
        print('PASS host-observed file write-open')
        print('PASS documentation-IP connection attempt:', connects[-1]['result'])
        break
    time.sleep(1)
else:
    raise RuntimeError('Missing host evidence: exec=' + str(len(execs)) + ' connect=' + str(len(connects)) + ' write=' + str(len(writes)))
