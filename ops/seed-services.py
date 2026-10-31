"""Idempotent lab initialization. Secrets are never printed."""
import os
import json
from pathlib import Path
import subprocess
import sys
import time
import requests
from dotenv import load_dotenv

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
load_dotenv(ROOT/'.env')
from app.lab_services import gitea,publish_file,mutate_gitea,mutate_cloud,GITEA
state_file=ROOT/'runtime/collector/state.json'
saved=json.loads(state_file.read_text()) if state_file.exists() else {}
applied={m['action'] for m in saved.get('world',{}).get('mutations',[]) if m.get('ok')}

for _ in range(60):
    try:
        if requests.get(GITEA+'/version',timeout=2).ok:break
    except requests.RequestException:pass
    time.sleep(1)
else:raise RuntimeError('Gitea did not become ready')
if not requests.get(GITEA+'/user',auth=('socadmin',os.environ['GITEA_ADMIN_PASSWORD']),timeout=5).ok:
    result=subprocess.run(['docker','compose','exec','-T','forge','gitea','admin','user','create','--username','socadmin','--password',os.environ['GITEA_ADMIN_PASSWORD'],'--email','soc@corp.local','--admin','--must-change-password=false'],cwd=ROOT,capture_output=True,text=True)
    if result.returncode:raise RuntimeError('Gitea account initialization failed: '+result.stderr[-300:])
if requests.get(GITEA+'/orgs/northstar',timeout=5).status_code==404:
    gitea('POST','/orgs',{'username':'northstar','full_name':'Northstar Systems','visibility':'public','description':'Corporate engineering and operations'})
if requests.get(GITEA+'/repos/northstar/backup-scripts',timeout=5).status_code==404:
    gitea('POST','/orgs/northstar/repos',{'name':'backup-scripts','description':'Backup operations and cloud migration','auto_init':True,'default_branch':'main','private':False})
files={'README.md':'# Northstar / Backup Operations\n\nOwner: IT Operations\nDomain: CORP.LOCAL\nBackup host: backup01\nAWS local: http://172.27.66.50:4566\n\nSWEETBERRY_CANARY_DECOY\n',
       'backup.sh':'# SWEETBERRY_CANARY_DECOY\n# Operations documentation, not executable backup logic.\n'}
for name,default in files.items():
    result=subprocess.run(['docker','compose','exec','-T','forge','git','-c','safe.directory=*','--git-dir=/srv/legacy/repos/backup-scripts.git','show','HEAD:'+name],cwd=ROOT,capture_output=True,text=True)
    publish_file(name,result.stdout if result.returncode==0 else default)
for action in ('expose_repository_notes','expose_cloud_map'):
    if action in applied:mutate_gitea(action)
issues=gitea('GET','/repos/northstar/backup-scripts/issues').json()
for title,body in [('Migrate backup inventory to object storage','Endpoint: http://172.27.66.50:4566\nBucket: corp-backups\nOwner: svc_backup\nSWEETBERRY_CANARY_DECOY'),('Review diagnostic intake workflow','Support portal: http://172.27.66.80\nAssistant: http://172.27.66.70\nSynthetic operations exercise.')]:
    if title not in {r['title'] for r in issues}:gitea('POST','/repos/northstar/backup-scripts/issues',{'title':title,'body':body})
for _ in range(30):
    result=subprocess.run(['docker','compose','exec','-T','cloud','python','/opt/cloud/seed.py'],cwd=ROOT,capture_output=True,text=True)
    if result.returncode==0:break
    time.sleep(1)
else:raise RuntimeError('Moto initialization failed: '+result.stderr[-400:])
for action in ('expose_cloud_inventory','expose_cloud_credential'):
    if action in applied:
        if not mutate_cloud(action)['ok']:raise RuntimeError('Failed to restore cloud bait')
print('Gitea organization, repository, issues and Moto fixtures initialized; secrets omitted.')
