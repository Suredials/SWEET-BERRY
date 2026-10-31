"""Append-only evidence with a rebuildable SQLite query index."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import threading
import time
import uuid
from .correlation import Correlator

SENSITIVE = re.compile(r'password|passwd|authorization|api.?key|secret|broker.?token|admin.?token', re.I)


def redact(value):
    if isinstance(value, dict):
        return {str(k): '[redacted]' if SENSITIVE.search(str(k)) else redact(v) for k,v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


class Telemetry:
    def __init__(self, root: Path):
        self.root = root
        self.folder = root / 'runtime/telemetry'
        self.folder.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.folder / 'index.sqlite', check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=NORMAL')
        self.db.executescript('''CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY, timestamp REAL, sensor TEXT, asset TEXT, kind TEXT,
          source TEXT, request_id TEXT, process_key TEXT, canary_id TEXT, mode TEXT,
          raw_file TEXT, raw_offset INTEGER, document TEXT);
          CREATE INDEX IF NOT EXISTS event_time ON events(timestamp DESC);
          CREATE INDEX IF NOT EXISTS event_source ON events(source,timestamp);
          CREATE INDEX IF NOT EXISTS event_asset_time ON events(asset,timestamp);
          CREATE INDEX IF NOT EXISTS event_process ON events(process_key,timestamp);
          CREATE INDEX IF NOT EXISTS event_request ON events(request_id,timestamp);
          CREATE INDEX IF NOT EXISTS event_canary ON events(canary_id,timestamp);
          CREATE TABLE IF NOT EXISTS cursors (name TEXT PRIMARY KEY, inode INTEGER, offset INTEGER);
          CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, source TEXT, updated REAL, document TEXT);
          CREATE TABLE IF NOT EXISTS canaries (id TEXT PRIMARY KEY, artifact TEXT, created REAL, document TEXT);''')
        self.db.commit()
        self.status = {'state':'ready', 'last_event':None, 'ingested':0, 'errors':0, 'expired_segments':0}
        self.segment = self.folder / ('evidence-' + str(time.time_ns()) + '.jsonl')
        self.observers = []
        self.correlator = Correlator()
        self.correlation_dirty=True
        self.correlation_stop=threading.Event()
        for record in reversed(self.db.execute('SELECT document FROM events ORDER BY timestamp DESC LIMIT 2000').fetchall()):
            self.correlator.observe(json.loads(record[0]))

    def record(self, document: dict) -> dict:
        row = redact(copy.deepcopy(document))
        row.setdefault('event_id', uuid.uuid4().hex)
        row.setdefault('timestamp', time.time())
        row.setdefault('sensor','application')
        row.setdefault('asset',row.get('container',row.get('target_host','unknown')))
        row.setdefault('kind',row.get('action','observation'))
        metadata=row.get('payload',{}).get('metadata',{}) if isinstance(row.get('payload'),dict) else row.get('metadata',{})
        if isinstance(metadata,dict) and metadata.get('maintenance'):
            row['original_kind']=row['kind'];row['kind']='maintenance'
        row.setdefault('source_ip','unattributed')
        row.setdefault('mode','live')
        row.setdefault('trust','application-untrusted')
        encoded = (json.dumps(row,ensure_ascii=False) + '\n').encode('utf-8')
        if len(encoded) > 180000:
            row = {k:v for k,v in row.items() if k not in {'body','response_body','raw','payload'}}
            row['truncated'] = True
            encoded = (json.dumps(row,ensure_ascii=False)+'\n').encode('utf-8')
        with self.lock:
            if self.segment.exists() and self.segment.stat().st_size >= 64*1024*1024:
                self.segment = self.folder / ('evidence-' + str(time.time_ns()) + '.jsonl')
                self.prune()
            with self.segment.open('ab') as stream:
                offset = stream.tell()
                stream.write(encoded)
            ref = {'file':self.segment.name,'offset':offset}
            row['evidence_ref'] = ref
            self.db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (row['event_id'],row['timestamp'],row['sensor'],row['asset'],row['kind'],row['source_ip'],
                 row.get('request_id'),row.get('process_key'),row.get('canary_id'),row['mode'],
                 self.segment.name,offset,json.dumps(row,ensure_ascii=False)))
            self.db.commit()
            self.status.update(last_event=time.time(),ingested=self.status['ingested']+1)
        self.correlator.observe(row)
        if row.get('sensor') in {'webedge','forge','cloud'} or row.get('kind') in {'php_request_end','php_request_start','ssh_backend_link','network_local','process_fork','observer_attached'}:
            self.correlation_dirty=True
        return row

    def start(self):
        def work():
            while not self.correlation_stop.wait(.5):
                if not self.correlation_dirty:continue
                self.correlation_dirty=False
                try:self.refresh_correlations()
                except Exception:
                    self.status['errors']+=1
                    self.correlation_dirty=True
        threading.Thread(target=work,daemon=True,name='evidence-correlation').start()

    def close(self):self.correlation_stop.set()

    def refresh_correlations(self):
        with self.lock:
            rows=self.db.execute("SELECT id,document FROM events WHERE asset IN ('linux','webtrap','forge','cloud') AND timestamp>? ORDER BY timestamp DESC LIMIT 2000",(time.time()-120,)).fetchall()
            for event_id,encoded in rows:
                row=json.loads(encoded)
                link=self.correlator.resolve(row)
                if not link or row.get('correlation')==link['correlation']:continue
                row['observed_source_ip']=row['source_ip']
                row.update(link)
                if row.get('process_key') in self.correlator.parents:row['parent_process_key']=self.correlator.parents[row['process_key']]
                self.db.execute('UPDATE events SET source=?,request_id=?,document=? WHERE id=?',
                    (row['source_ip'],row.get('request_id'),json.dumps(row,ensure_ascii=False),event_id))
                if getattr(self,'on_correlated',None) and row.get('kind') in {'http_response','process_exec'}:self.on_correlated(row)
            self.db.commit()

    def prune(self):
        segments = sorted(self.folder.glob('evidence-*.jsonl'))
        while len(segments) > 63:
            expired = segments.pop(0)
            expired.unlink()
            self.status['expired_segments'] += 1

    def cursor(self,name):
        with self.lock:
            return self.db.execute('SELECT inode,offset FROM cursors WHERE name=?',(name,)).fetchone()

    def set_cursor(self,name,inode,offset):
        with self.lock:
            self.db.execute('INSERT OR REPLACE INTO cursors VALUES (?,?,?)',(name,inode,offset))
            self.db.commit()

    def query(self, *, source='', asset='', kind='', process_key='', request_id='', canary_id='', mode='live', limit=100, before=None, before_id='', important=False):
        clauses, values = [], []
        for key,value in [('source',source),('asset',asset),('kind',kind),('process_key',process_key),('request_id',request_id),('canary_id',canary_id),('mode',mode)]:
            if value:
                clauses.append(key+'=?'); values.append(value)
        if before is not None:
            clauses.append('timestamp < ?'); values.append(before)
        if before_id:
            with self.lock:cursor=self.db.execute('SELECT timestamp FROM events WHERE id=?',(before_id,)).fetchone()
            if cursor:
                clauses.append('(timestamp < ? OR (timestamp = ? AND id < ?))');values.extend([cursor[0],cursor[0],before_id])
            else:return []
        if important:clauses.append("kind NOT IN ('file_open','process_exit','raw_log','container_log','decision','operator_profile','mutation','stats','maintenance')")
        values.append(max(1,min(int(limit),300)))
        with self.lock:
            records = self.db.execute('SELECT document FROM events'+(' WHERE '+' AND '.join(clauses) if clauses else '')+' ORDER BY timestamp DESC,id DESC LIMIT ?',values).fetchall()
        output=[]
        for record in records:
            row=json.loads(record[0])
            row.update(self.correlator.resolve(row))
            if row.get('process_key') in self.correlator.parents:row['parent_process_key']=self.correlator.parents[row['process_key']]
            output.append(row)
        return output

    def evidence(self,event_id):
        with self.lock:
            row = self.db.execute('SELECT document,raw_file,raw_offset FROM events WHERE id=?',(event_id,)).fetchone()
        if not row:
            return None
        document = json.loads(row[0])
        document.update(self.correlator.resolve(document))
        document['raw_available'] = (self.folder / row[1]).is_file()
        return document

    def register_canary(self,artifact,channel='artifact'):
        with self.lock:
            row = self.db.execute('SELECT document FROM canaries WHERE artifact=?',(artifact,)).fetchone()
            if row:
                return json.loads(row[0])
            item = {'canary_id':'SWEETBERRY_CANARY_DECOY_'+uuid.uuid4().hex[:12], 'artifact':artifact,
                    'channel':channel,'created':time.time()}
            self.db.execute('INSERT INTO canaries VALUES (?,?,?,?)',(item['canary_id'],artifact,item['created'],json.dumps(item)))
            self.db.commit()
            return item

    def incident_update(self,report):
        sources = sorted({r.get('source_ip') for r in report.get('evidence',[]) if r.get('source_ip') and r.get('source_ip') not in {'unattributed','local'}})
        output=[]
        with self.lock:
            for source in sources:
                active=self.db.execute('SELECT id FROM incidents WHERE source=? AND updated>? ORDER BY updated DESC LIMIT 1',(source,report['timestamp']-1800)).fetchone()
                incident_id = active[0] if active else 'incident-'+uuid.uuid4().hex[:12]
                previous = self.db.execute('SELECT document FROM incidents WHERE id=?',(incident_id,)).fetchone()
                previous = json.loads(previous[0]) if previous else {'revision':0,'history':[]}
                item = {'incident_id':incident_id,'source_ip':source,'revision':previous['revision']+1,
                        'title':report['title'],'summary':report['summary'],'severity':report['severity'],
                        'confidence':report['confidence'],'findings':report['findings'],
                        'recommendations':report['recommendations'],'uncertainties':report['uncertainties'],
                        'operator_assessment':report.get('operator_assessment'),
                        'updated':report['timestamp'],'mode':report['mode'],
                        'scope':'source-specific incident; multi-source reports do not establish shared identity',
                        'history':(previous.get('history',[])+[{'revision':previous['revision']+1,'timestamp':report['timestamp'],'mode':report['mode'],'title':report['title']}])[-20:]}
                self.db.execute('INSERT OR REPLACE INTO incidents VALUES (?,?,?,?)',(incident_id,source,item['updated'],json.dumps(item,ensure_ascii=False)))
                output.append(item)
            self.db.commit()
        return output

    def incidents(self):
        with self.lock:
            return [json.loads(row[0]) for row in self.db.execute('SELECT document FROM incidents ORDER BY updated DESC LIMIT 50')]

    def intelligence(self):
        rows=self.query(limit=300,important=True)
        indicators={}
        for row in rows:
            candidates=[('destination_ip',row.get('destination')),('domain',row.get('dns',{}).get('rrname') if isinstance(row.get('dns'),dict) else None),('sha256',row.get('sha256')),('canary',row.get('canary_id'))]
            dns=row.get('dns',{})
            if isinstance(dns,dict):
                for question in dns.get('queries',[]):
                    if isinstance(question,dict):candidates.append(('domain',question.get('rrname')))
            for kind,value in candidates:
                if not value or not isinstance(value,str): continue
                key=(kind,value)
                item=indicators.setdefault(key,{'type':kind,'value':value,'first_seen':row['timestamp'],'last_seen':row['timestamp'],'count':0,'assets':[],'evidence_ids':[],'assessment':'observed in laboratory; no external reputation claim'})
                item['count']+=1;item['first_seen']=min(item['first_seen'],row['timestamp']);item['last_seen']=max(item['last_seen'],row['timestamp'])
                if row['asset'] not in item['assets']:item['assets'].append(row['asset'])
                if len(item['evidence_ids'])<8:item['evidence_ids'].append(row['event_id'])
        incidents=self.incidents()
        for item in indicators.values():
            refs=set(item['evidence_ids']);annotations=[]
            for incident in incidents:
                for finding in incident.get('findings',[]):
                    if refs.intersection(finding['evidence_ids']):annotations.append({'incident_id':incident['incident_id'],'hypothesis':finding['hypothesis'],'confidence':finding['confidence']})
            item['soc_findings']=annotations[:3]
        return {'scope':'Latest 300 relevant indexed observations; full history available in telemetry queries', 'indicators':list(indicators.values()),'incidents':incidents}

    def snapshot(self):
        with self.lock:
            total=self.db.execute('SELECT count(*) FROM events').fetchone()[0]
            by_sensor=dict(self.db.execute('SELECT sensor,count(*) FROM events GROUP BY sensor'))
            canaries=[json.loads(row[0]) for row in self.db.execute('SELECT document FROM canaries ORDER BY created DESC LIMIT 100')]
        fields={'event_id','timestamp','sensor','asset','kind','source_ip','correlation','request_id','canary_id','process_key','parent_process_key','executable','path','destination','port'}
        recent=[{key:value for key,value in row.items() if key in fields} for row in self.query(limit=60,important=True)]
        return {'status':dict(self.status),'total':total,'by_sensor':by_sensor,'canaries':canaries,'recent':recent}
