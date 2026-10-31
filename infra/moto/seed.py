"""Local emulated AWS only. Data and credentials are unmistakable decoys."""
import json
import os
from pathlib import Path
import sys
import boto3

ROOT=Path('/srv/data')
MARKER='SWEETBERRY_CANARY_DECOY'
def client(service):return boto3.client(service,endpoint_url='http://127.0.0.1:5000',region_name='us-east-1',aws_access_key_id=MARKER,aws_secret_access_key=MARKER)

def seed():
    s3,iam=client('s3'),client('iam')
    if 'corp-backups' not in [r['Name'] for r in s3.list_buckets()['Buckets']]:s3.create_bucket(Bucket='corp-backups')
    # Deliberately public read-only lab bucket, preserving legacy unsigned reads.
    s3.put_bucket_policy(Bucket='corp-backups',Policy=json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':'*','Action':['s3:GetObject'],'Resource':['arn:aws:s3:::corp-backups/*']}]}))
    users={r['UserName'] for r in iam.list_users()['Users']}
    for name in ('svc_backup','build_service','cloud_reader'):
        if name not in users:iam.create_user(UserName=name,Tags=[{'Key':'lab','Value':MARKER}])
    iam.put_user_policy(UserName='svc_backup',PolicyName='BackupReadOnly',PolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':['s3:ListBucket','s3:GetObject'],'Resource':['arn:aws:s3:::corp-backups','arn:aws:s3:::corp-backups/*']}]}))
    put('backup-index.json',json.dumps({'environment':'lab','project':'cloud-migration','marker':MARKER}))
    for file in ROOT.glob('*'):
        if file.is_file():put(file.name,file.read_text())

def put(name,content):
    registry=ROOT/'registry/canaries.json'
    identities=json.loads(registry.read_text()) if registry.exists() else {}
    client('s3').put_object(Bucket='corp-backups',Key=name,Body=content.encode(),Metadata={'sweetberry-canary':identities.get(name,MARKER+'_'+name.replace('.','_'))})

def mutate(action):
    seed()
    data={'expose_cloud_inventory':('inventory.csv','object,classification\nbackup-index.json,internal\ncloud_credentials.txt,canary\n'),
          'expose_cloud_credential':('cloud_credentials.txt','AWS_ACCESS_KEY_ID=SWEETBERRY_CANARY_DECOY\nAWS_SECRET_ACCESS_KEY=SWEETBERRY_CANARY_DECOY\nAWS_ENDPOINT_URL=http://172.27.66.50:4566\n# Inert lab identity; never use against real AWS\n')}
    name,content=data[action]
    canary_id=os.getenv('SWEETBERRY_CANARY_ID',MARKER+'_'+name.replace('.','_'))
    if action=='expose_cloud_credential':content=content.replace('AWS_ACCESS_KEY_ID=SWEETBERRY_CANARY_DECOY\n','AWS_ACCESS_KEY_ID='+canary_id+'\n')
    registry=ROOT/'registry/canaries.json';registry.parent.mkdir(exist_ok=True)
    identities=json.loads(registry.read_text()) if registry.exists() else {}
    identities[name]=canary_id;registry.write_text(json.dumps(identities))
    (ROOT/name).write_text(content)
    put(name,content)
    print(json.dumps({'action':action,'artifact':name,'backend':'Moto','marker':MARKER}))

if __name__=='__main__':
    mutate(sys.argv[1]) if len(sys.argv)>1 else seed()
