"""Two benign simultaneous sessions must retain distinct Cowrie correlation IDs."""
import time
import paramiko
import requests

started=time.time()
clients=[];shells=[]
try:
    for label in ('A','B'):
        client=paramiko.SSHClient();client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect('172.27.66.20',port=22,username='analyst',password='SWEETBERRY_CANARY_DECOY_LabOnly!',timeout=10,allow_agent=False,look_for_keys=False)
        clients.append(client);shells.append(client.invoke_shell())
    time.sleep(1)
    for label,shell in zip(('A','B'),shells):shell.send("/usr/bin/printf 'SWEETBERRY_CANARY_DECOY session-"+label+"\\n'; id\n")
    time.sleep(3)
finally:
    for shell in shells:shell.close()
    for client in clients:client.close()
for _ in range(30):
    rows=requests.get('http://172.27.66.1:8501/api/telemetry',params={'asset':'linux','kind':'process_exec','limit':200},timeout=15).json()
    groups={label:[r for r in rows if r['timestamp']>=started and r.get('executable')=='/usr/bin/printf' and 'session-'+label in r.get('argv_preview','') and r.get('ssh_session')] for label in ('A','B')}
    if all(groups.values()):
        a,b=groups['A'][0],groups['B'][0]
        assert a['ssh_session']!=b['ssh_session']
        assert a['correlation']==b['correlation']=='cowrie_backend_tuple_process'
        print('PASS two concurrent SSH sessions retain distinct backend/process correlation')
        print('SESSION_A',a['ssh_session'],'SESSION_B',b['ssh_session'])
        break
    time.sleep(.5)
else:raise RuntimeError('SSH process correlation missing for one or both sessions')
