"""Fixed-upstream evidence gateway. It never executes uploaded content."""
import hashlib
import html
import json
import os
from pathlib import Path
import re
import threading
import time
import uuid
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit
import requests

ROLE=os.environ.get('EDGE_ROLE','webedge')
UPSTREAM=os.environ['UPSTREAM'].rstrip('/')
LOG=Path('/var/log/lure');LOG.mkdir(parents=True,exist_ok=True)
LOCK=threading.Lock()
PUBLIC={'forge':'http://172.27.66.40:3000','cloud':'http://172.27.66.50:4566','webedge':'http://172.27.66.80','chatbot':'http://172.27.66.70'}
DROP={'host','content-length','connection','transfer-encoding','accept-encoding','x-forwarded-for','x-real-ip','x-sweetberry-request-id','x-chat-broker-token'}


def log(row):
    with LOCK:
        file=LOG/'events.jsonl'
        if file.exists() and file.stat().st_size>64*1024*1024:
            file.replace(LOG/('events-'+str(time.time_ns())+'.jsonl'))
        archives=sorted(LOG.glob('events-*.jsonl'))
        for old in archives[:-8]:old.unlink()
        with file.open('a') as stream:stream.write(json.dumps(row,ensure_ascii=False)+'\n')


class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.0'
    def log_message(self,*args):pass
    def reply(self,status,body,content_type='application/json',request_id=''):
        if not isinstance(body,bytes):body=json.dumps(body,ensure_ascii=False).encode()
        self.send_response(status);self.send_header('Content-Type',content_type)
        self.send_header('Content-Length',str(len(body)));self.send_header('X-Content-Type-Options','nosniff')
        if request_id:self.send_header('X-SweetBerry-Request-ID',request_id)
        self.end_headers()
        if self.command!='HEAD':self.wfile.write(body)

    def uploads(self,body,content_type,event):
        if 'multipart/form-data' not in content_type:return
        message=BytesParser(policy=policy.default).parsebytes(('Content-Type: '+content_type+'\r\nMIME-Version: 1.0\r\n\r\n').encode()+body)
        files=[];folder=LOG/'quarantine';folder.mkdir(exist_ok=True)
        for part in message.iter_parts() if message.is_multipart() else []:
            name=part.get_filename()
            if name is None:continue
            payload=part.get_payload(decode=True) or b''
            digest=hashlib.sha256(payload).hexdigest()
            item={'filename':name[:200],'size':len(payload),'sha256':digest,'retained':False}
            if len(payload)<=5*1024*1024:
                path=folder/(digest+'.quarantined')
                if not path.exists():path.write_bytes(payload)
                item['retained']=True
            files.append(item)
            event['sha256']=digest
        event['uploads']=files
        samples=sorted(folder.glob('*.quarantined'),key=lambda p:p.stat().st_mtime)
        total=sum(p.stat().st_size for p in samples)
        for path in samples:
            if total<=256*1024*1024:break
            size=path.stat().st_size;path.unlink();total-=size

    def handle_request(self):
        path=urlsplit(self.path)
        if path.path=='/health':return self.reply(200,{'status':'ok','role':ROLE})
        request_id=uuid.uuid4().hex
        source=self.client_address[0]
        try:length=int(self.headers.get('Content-Length','0'))
        except ValueError:return self.reply(400,{'error':'invalid length'})
        if length<0 or length>6*1024*1024:return self.reply(413,{'error':'request too large'})
        body=self.rfile.read(length)
        stamp=time.time()
        event={'timestamp':stamp,'session_id':'live:'+source,'source_ip':source,'source_port':self.client_address[1],'sensor':ROLE,
            'target_host':{'forge':'git01','cloud':'cloud01','webedge':'webtrap01','chatbot':'assistant01'}[ROLE],
            'request_id':request_id,'kind':'http_request','action':'http_contact','target':path.path[:256],
            'method':self.command,'query':path.query[:8192],
            'headers':{k:'[redacted]' if re.search('authorization|cookie|token|secret|key',k,re.I) else v[:4096] for k,v in self.headers.items()},
            'body':body[:65536].decode('utf-8',errors='replace'),'body_size':length,'truncated':length>65536,
            'metadata':{'maintenance':source in {'172.27.66.1','172.30.67.1','127.0.0.1'}}}
        self.uploads(body,self.headers.get('Content-Type',''),event)
        if ROLE=='webedge':
            event['action']='web_upload' if self.command=='POST' and path.path=='/upload.php' else 'web_script_request' if path.path.startswith('/uploads/') and path.path.endswith('.php') else 'web_visit'
        if ROLE=='forge':event['action']='repo_read' if any(p in path.path for p in ('git-upload-pack','/raw/','/src/','/api/files/')) else 'repo_discovery'
        if ROLE=='cloud':
            action=parse_qs((body.decode(errors='replace') if self.command=='POST' else path.query)).get('Action',[''])[0]
            event['aws_action']=action or ('ListBuckets' if path.path=='/' else 'GetObject' if '/' in path.path.strip('/') else 'ListObjectsV2')
            event['action']='secret_access' if 'cloud_credentials.txt' in path.path else 'cloud_inventory_read' if 'inventory.csv' in path.path else 'cloud_buckets' if path.path in {'/','/api/buckets'} else 'cloud_object_read'
            if action:event['action']='cloud_account_discovery'
            elif 'list-type' in path.query:event['action']='cloud_objects'
            credential=re.search(r'Credential=([^/ ,]+)',self.headers.get('Authorization',''))
            if credential:
                event['credential_id']=credential[1]
                if credential[1].startswith('SWEETBERRY_CANARY_DECOY'):event['canary_id']=credential[1]
            if 'cloud_credentials.txt' in path.path:event['canary_id']='SWEETBERRY_CANARY_DECOY_cloud_credentials'
        if ROLE=='chatbot':event['action']='chat_request' if self.command=='POST' else 'chat_visit'
        if ROLE=='chatbot' and path.path in {'/api/status','/chat.js'}:event['metadata']['maintenance']=True
        ua=self.headers.get('User-Agent','').casefold()
        event['metadata']['client_family']='self_reported_agent' if any(p in ua for p in ('langchain','autogen','codex','claude-code','agent')) else 'browser' if any(p in ua for p in ('mozilla','chrome','firefox','safari')) else 'cli_or_sdk' if any(p in ua for p in ('curl','python-requests','aiohttp','botocore','aws-cli','git/')) else 'unknown'
        log({**event,'kind':'http_request_started'})
        upstream_path=path.path+('?' + path.query if path.query else '')
        response_headers={}
        try:
            if ROLE=='cloud' and (path.path.startswith('/moto-api') or self.command not in {'GET','HEAD','POST'} or self.command=='POST' and not event['aws_action'].startswith(('Get','List'))):
                status,content,content_type=403,b'<Error><Code>AccessDenied</Code><Message>Read-only account</Message></Error>','application/xml'
            elif ROLE=='forge' and path.path=='/api/repos':
                status,content,content_type=200,json.dumps({'repositories':[{'name':'backup-scripts','clone_url':PUBLIC['forge']+'/northstar/backup-scripts.git'}]}).encode(),'application/json'
            elif ROLE=='forge' and path.path=='/api/files':
                response=requests.get(UPSTREAM+'/api/v1/repos/northstar/backup-scripts/contents',timeout=10)
                status,content,content_type=response.status_code,response.content,'application/json'
            elif ROLE=='cloud' and path.path=='/api/buckets':
                status,content,content_type=200,b'{"buckets":["corp-backups"]}','application/json'
            elif ROLE=='cloud' and path.path=='/api/buckets/corp-backups/objects':
                status,content,content_type=200,b'{"objects":["backup-index.json","inventory.csv","cloud_credentials.txt"]}','application/json'
            else:
                if ROLE=='forge':
                    upstream_path=upstream_path.replace('/repos/backup-scripts.git','/northstar/backup-scripts.git',1)
                    if path.path.startswith('/api/files/'):upstream_path='/northstar/backup-scripts/raw/branch/main/'+quote(path.path.split('/api/files/',1)[1],safe='')
                if ROLE=='cloud' and path.path.startswith('/api/buckets/corp-backups/objects/'):
                    upstream_path='/corp-backups/'+quote(path.path.split('/objects/',1)[1],safe='')
                headers={k:v for k,v in self.headers.items() if k.lower() not in DROP}
                headers.update({'X-Forwarded-For':source,'X-SweetBerry-Request-ID':request_id})
                if ROLE=='chatbot':headers['X-Chat-Broker-Token']=os.environ.get('CHAT_BROKER_TOKEN','')
                response=requests.request(self.command,UPSTREAM+upstream_path,headers=headers,data=body,timeout=(4,50),allow_redirects=False,stream=True)
                chunks=[];received=0;limited=False
                for chunk in response.iter_content(65536):
                    received+=len(chunk)
                    if received>8*1024*1024:limited=True;break
                    chunks.append(chunk)
                status,content,content_type=response.status_code,b''.join(chunks),response.headers.get('Content-Type','application/octet-stream')
                if ROLE=='cloud' and response.headers.get('x-amz-meta-sweetberry-canary'):event['canary_id']=response.headers['x-amz-meta-sweetberry-canary']
                response.close()
                if limited:
                    status,content,content_type=502,b'{"error":"upstream response exceeded evidence gateway limit"}','application/json'
                    event['upstream_response_limited']=True
                response_headers={k:v for k,v in response.headers.items() if k.lower() in {'location','set-cookie','cache-control'}}
                if 'location' in {k.lower() for k in response_headers}:
                    response_headers={k:v.replace(UPSTREAM,PUBLIC[ROLE]) for k,v in response_headers.items()}
        except requests.RequestException as exc:
            status,content,content_type=502,json.dumps({'error':type(exc).__name__}).encode(),'application/json'
        event.update(status=status,duration_ms=round((time.time()-stamp)*1000,2),kind='http_response',
                     response_body=content[:65536].decode('utf-8',errors='replace'),response_truncated=len(content)>65536)
        event['metadata'].update(evidence='confirmed' if status<400 else 'attempted',status=status,request_id=request_id)
        log(event)
        self.send_response(status)
        self.send_header('Content-Type',content_type);self.send_header('Content-Length',str(len(content)))
        self.send_header('X-SweetBerry-Request-ID',request_id);self.send_header('X-Content-Type-Options','nosniff')
        for k,v in response_headers.items():self.send_header(k,v)
        self.end_headers()
        if self.command!='HEAD':self.wfile.write(content)

    do_GET=handle_request
    do_POST=handle_request
    do_HEAD=handle_request
    do_PUT=handle_request
    do_DELETE=handle_request
    do_OPTIONS=handle_request


ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
