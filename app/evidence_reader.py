"""Independent raw-log reader; checkpoints are committed after evidence writes."""
import json
import datetime
import hashlib
import subprocess
from pathlib import Path
import threading
import time


class EvidenceReader:
    def __init__(self, root: Path, telemetry, live=False):
        self.root,self.telemetry,self.live=root,telemetry,live
        self.stop=threading.Event()
        self.processes=[]
        self.status={'state':'starting' if live else 'offline','files':{},'errors':0}

    def start(self):
        if self.live:
            threading.Thread(target=self.run,daemon=True,name='evidence-reader').start()
            for role in ('webtrap','forge','cloud','guard','dns'):
                threading.Thread(target=self.docker_logs,args=(role,),daemon=True,name='docker-evidence-'+role).start()

    def run(self):
        while not self.stop.wait(.5):
            paths=[('cowrie','cowrie',self.root/'runtime/cowrie/log/cowrie/cowrie.json'),
                   ('samba','dc',self.root/'runtime/dc/auth.json'),
                   ('samba-files','dc',self.root/'runtime/dc/files.log'),
                   ('suricata','network',self.root/'runtime/network/eve.json')]
            paths += [(role,role,self.root/f'runtime/{role}/events.jsonl') for role in ('portal','forge','cloud','canary','linux','webedge','chatbot','broker')]
            for sensor,asset,path in paths:
                try:self.read(sensor,asset,path)
                except (OSError,ValueError,TypeError):
                    self.status['errors']+=1
                    self.status['files'][sensor]='read error; retrying'
            self.status['state']='reading'

    def read(self,sensor,asset,path):
        if not path.exists():
            self.status['files'][sensor]='not present'
            return
        stat=path.stat();cursor=self.telemetry.cursor(str(path))
        offset=cursor[1] if cursor and cursor[0]==stat.st_ino and cursor[1]<=stat.st_size else 0
        with path.open('rb') as stream:
            stream.seek(offset)
            for _ in range(400):
                begin=stream.tell();raw=stream.readline(262145)
                if not raw or not raw.endswith(b'\n'):
                    if len(raw)>262144:
                        while raw and not raw.endswith(b'\n'):raw=stream.readline(262145)
                        self.telemetry.record({'sensor':sensor,'asset':asset,'kind':'oversized_log_line','truncated':True})
                        continue
                    stream.seek(begin);break
                text=raw.decode('utf-8',errors='replace')
                try:body=json.loads(text[text.find('{'):]) if '{' in text else {'message':text[:65536]}
                except ValueError:body={'message':text[:65536],'parse_error':True}
                kind=body.get('event_type',body.get('kind',body.get('action',body.get('eventid','raw_log'))))
                source=body.get('source_ip',body.get('src_ip',body.get('src_host','unattributed')))
                stamp=body.get('timestamp',body.get('utc_time'))
                if isinstance(stamp,(int,float)):timestamp=stamp
                else:
                    try:
                        parsed=datetime.datetime.fromisoformat(str(stamp).replace('Z','+00:00'))
                        timestamp=(parsed if parsed.tzinfo else parsed.replace(tzinfo=datetime.timezone.utc)).timestamp()
                    except ValueError:timestamp=time.time()
                event={'sensor':sensor,'asset':asset,'kind':str(kind)[:100],'source_ip':source,
                       'trust':'host-network' if sensor=='suricata' else 'sensor-log' if sensor in {'cowrie','samba','samba-files','canary','webedge','broker'} else 'application-untrusted',
                       'payload':body,'timestamp':timestamp,'observed_at':time.time()}
                for key in ('request_id','canary_id','sha256','destination','process_key','parent_process_key'):
                    if key in body:event[key]=body[key]
                if sensor=='suricata':
                    event.update(flow_id=str(body.get('flow_id','')),destination=body.get('dest_ip'),port=body.get('dest_port'))
                    if body.get('dns'):event['dns']=body['dns']
                    if body.get('fileinfo',{}).get('sha256'):event['sha256']=body['fileinfo']['sha256']
                if sensor=='cowrie' and body.get('eventid')=='cowrie.proxy.backend_connected':
                    event.update(kind='ssh_backend_link',session=body.get('session'),
                        local_ip=body.get('local_ip'),local_port=body.get('local_port'),backend_ip=body.get('backend_ip'))
                self.telemetry.record(event)
            self.telemetry.set_cursor(str(path),stat.st_ino,stream.tell())
        self.status['files'][sensor]={'state':'reading','updated':time.time(),'offset':stream.tell() if not stream.closed else stat.st_size}

    def docker_logs(self,role):
        since=str(time.time()-2)
        while not self.stop.is_set():
            process=None
            try:
                cid=subprocess.check_output(['docker','compose','ps','-q',role],cwd=self.root,text=True,timeout=4).strip()
                if not cid:raise ValueError('Container not running')
                process=subprocess.Popen(['docker','logs','--timestamps','--since',since,'-f',cid],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,errors='replace')
                self.processes.append(process)
                for line in iter(lambda:process.stdout.readline(131073),''):
                    if self.stop.is_set():break
                    stamp,text=line.split(' ',1) if ' ' in line else ('',line)
                    try:timestamp=datetime.datetime.fromisoformat(stamp.replace('Z','+00:00')).timestamp();since=stamp
                    except ValueError:timestamp=time.time()
                    try:body=json.loads(text[text.index('{'):])
                    except (ValueError,IndexError):body={'message':text[:65536],'truncated':len(text)>65536}
                    if not isinstance(body,dict):body={'message':str(body)[:65536]}
                    self.telemetry.record({'event_id':hashlib.sha256((cid+line).encode()).hexdigest(),
                        'timestamp':body.get('timestamp',timestamp) if isinstance(body.get('timestamp',timestamp),(int,float)) else timestamp,
                        'sensor':'docker','asset':role,'container_id':cid,'kind':body.get('kind','container_log'),
                        'request_id':body.get('request_id'),'source_ip':body.get('source_ip','unattributed'),
                        'trust':'sensor-log' if role=='dns' else 'application-untrusted','dns':body.get('dns',{}),'destination':body.get('destination'),'payload':body})
                self.status['files']['docker:'+role]='reconnecting'
            except (OSError,ValueError,subprocess.SubprocessError):self.status['files']['docker:'+role]='unavailable; retrying'
            finally:
                if process and process.poll() is None:process.terminate()
                if process in self.processes:self.processes.remove(process)
            self.stop.wait(3)

    def close(self):
        self.stop.set()
        for process in list(self.processes):
            if process.poll() is None:process.terminate()
