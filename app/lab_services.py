"""Fixed Gitea publication operations; never execute model-provided commands."""
import base64
import json
import os
from pathlib import Path
import requests
import subprocess
from .telemetry import Telemetry

ROOT=Path(__file__).resolve().parents[1]
GITEA='http://172.30.67.40:3000/api/v1'


def gitea(method,path,body=None):
    response=requests.request(method,GITEA+path,auth=('socadmin',os.environ['GITEA_ADMIN_PASSWORD']),json=body,timeout=12)
    if response.status_code not in {200,201,204,409,422}:raise RuntimeError('Gitea HTTP '+str(response.status_code))
    return response


def publish_file(name,content):
    if '/' in name or name not in {'README.md','backup.sh','migration-notes.md','cloud-map.json','it-runbook.md'}:raise ValueError('Unsupported document')
    path='/repos/northstar/backup-scripts/contents/'+name
    response=requests.get(GITEA+path,timeout=10)
    body={'content':base64.b64encode(content.encode()).decode(),'message':'Publish operations documentation','branch':'main'}
    if response.status_code==200:
        existing=response.json()
        if base64.b64decode(existing['content']).decode()==content:return
        body['sha']=existing['sha']
    gitea('PUT' if response.status_code==200 else 'POST',path,body)


def mutate_gitea(action):
    from infra.lures.mutate import CONTENT
    name,content=CONTENT[action]
    registry=Telemetry(ROOT)
    canary=registry.register_canary('gitea:'+name,'repository-document')
    if name.endswith('.json'):
        document=json.loads(content)
        document.update(endpoint='http://172.27.66.50:4566',region='us-east-1',canary_id=canary['canary_id'])
        content=json.dumps(document,indent=2)
    else:content+='\n\nCanary: '+canary['canary_id']+'\n'
    publish_file(name,content)
    registry.record({'sensor':'publisher','asset':'forge','kind':'canary_published','canary_id':canary['canary_id'],'artifact':name,'trust':'deterministic-engine'})
    registry.db.close()
    return {'host':'git01','ok':True,'artifact':name,'canary_id':canary['canary_id']}


def mutate_cloud(action):
    names={'expose_cloud_inventory':'inventory.csv','expose_cloud_credential':'cloud_credentials.txt'}
    if action not in names:raise ValueError('Unsupported cloud mutation')
    registry=Telemetry(ROOT)
    canary=registry.register_canary('s3:corp-backups/'+names[action],'s3-object')
    result=subprocess.run(['docker','compose','exec','-T','-e','SWEETBERRY_CANARY_ID='+canary['canary_id'],
        'cloud','python3','/opt/cloud/seed.py',action],cwd=ROOT,capture_output=True,text=True,timeout=15)
    registry.record({'sensor':'publisher','asset':'cloud','kind':'canary_published','canary_id':canary['canary_id'],
        'artifact':names[action],'ok':result.returncode==0,'trust':'deterministic-engine'})
    registry.db.close()
    return {'host':'cloud01','ok':result.returncode==0,'artifact':names[action],'canary_id':canary['canary_id'],
            'detail':result.stderr[-500:] if result.returncode else 'Published to Moto S3'}
