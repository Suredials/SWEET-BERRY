"""Read Cowrie and Samba logs; capture only selected protocol metadata."""
import datetime
import json
import queue
import re
import subprocess
import threading
import time
from pathlib import Path
from .models import Event


def cowrie_event(row: dict) -> Event | None:
    source = row.get('src_ip')
    if not source or source.startswith('127.'):
        return None
    kind = row.get('eventid', '')
    action = {'cowrie.session.connect': 'ssh_connect', 'cowrie.login.success': 'ssh_login', 'cowrie.login.failed': 'ssh_auth_failure'}.get(kind)
    command = str(row.get('input', ''))[:4096]
    if kind == 'cowrie.command.input':
        first = command.strip().split(' ', 1)[0]
        action = {'uname': 'system_discovery', 'hostname': 'system_discovery', 'id': 'system_discovery',
                  'whoami': 'system_discovery', 'ls': 'file_discovery', 'find': 'file_discovery',
                  'cat': 'file_discovery', 'ip': 'network_discovery', 'ifconfig': 'network_discovery',
                  'ss': 'network_discovery', 'ps': 'process_discovery', 'env': 'environment_discovery',
                  'printenv': 'environment_discovery'}.get(first, 'shell_command')
        if first in {'cat', 'head', 'less'} and 'cloud_credentials.txt' in command:
            action = 'secret_access'
        elif first in {'cat', 'head', 'less'} and 'inventory.csv' in command:
            action = 'backup_access'
    if not action:
        return None
    stamp = row.get('timestamp', '')
    try:
        timestamp = datetime.datetime.fromisoformat(stamp.replace('Z', '+00:00')).timestamp()
    except (ValueError, TypeError, AttributeError):
        timestamp = time.time()
    return Event(timestamp=timestamp, session_id='live:' + source, source_ip=source, sensor='cowrie',
                 target_host='backup01', action=action, metadata={'input': command, 'ssh_session': row.get('session', '')})


def smb_event(line: str) -> Event | None:
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\|([^|]*)\|([^|]*)\|(\w+)\|([^|]*)\|(.*)', line)
    if not match:
        return None
    source, user, share, operation, status, path = match.groups()
    if source.startswith(('127.', '172.30.')) or status != 'ok' or operation not in {'connect', 'openat', 'pread'}:
        return None
    action = 'share_access' if operation == 'connect' else ('backup_access' if share.casefold().startswith('backups') else 'public_file_access')
    if operation in {'openat', 'pread'} and 'cloud_credentials.txt' in path:
        action = 'secret_access'
    return Event(timestamp=time.time(), session_id='live:' + source, source_ip=source, sensor='samba',
                 target_host='dc01', action=action, target=(share + '/' + path)[:256], metadata={'operation': operation})


def domain_auth_event(line):
    start = line.find('{')
    if start < 0:
        return None
    record = json.loads(line[start:])
    auth = record.get('Authentication')
    if not auth:
        return None
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', auth.get('remoteAddress', ''))
    if not match or match[1].startswith(('127.', '172.30.')):
        return None
    source = match[1]
    success = auth.get('status') == 'NT_STATUS_OK'
    return Event(timestamp=time.time(), session_id='live:' + source, source_ip=source, sensor='samba', target_host='dc01',
                 action='domain_authentication' if success else 'auth_failure', target=str(auth.get('clientAccount', ''))[:256],
                 metadata={'evidence': 'confirmed' if success else 'attempted', 'service': auth.get('serviceDescription', '')})


def canary_event(line):
    row = json.loads(line)
    source = row.get('src_host', '')
    if not source or source.startswith(('127.', '172.30.')) or row.get('logtype', 0) < 2000:
        return None
    logtype = row['logtype']
    authentication = logtype in {2000, 2001, 8001, 9001, 9002}
    if logtype == 20001:
        activity = str(row.get('logdata', {}).get('action', '')).casefold()
        authentication = 'auth' in activity or 'login' in activity
    protocol = {2000: 'FTP', 2001: 'FTP', 8001: 'MySQL', 9001: 'MSSQL', 9002: 'MSSQL', 9003: 'MySQL',
                14001: 'RDP', 17001: 'Redis', 20001: 'MongoDB'}.get(logtype, 'TCP')
    details = {key: value for key, value in row.get('logdata', {}).items() if 'pass' not in key.casefold()}
    try:
        timestamp = datetime.datetime.fromisoformat(row['utc_time']).replace(tzinfo=datetime.timezone.utc).timestamp()
    except (KeyError, ValueError):
        timestamp = time.time()
    return Event(timestamp=timestamp, session_id='live:' + source, source_ip=source, sensor='opencanary', target_host='services01',
                 action='service_auth_attempt' if authentication else 'decoy_protocol_contact', target=protocol,
                 metadata={'protocol': protocol, 'logtype': logtype, 'evidence': 'attempted' if authentication else 'observed', 'input': json.dumps(details)[:4096]})


def target_log_event(line, role):
    row = json.loads(line)
    if row.get('metadata',{}).get('maintenance'):
        return None
    if row.get('kind') == 'http_request_started':
        return None
    if role == 'linux':
        # The monitored shell can write its local log. It must never impersonate
        # another sensor or inject security actions into the privileged actor.
        row.update(sensor='integrity', action='file_integrity_change', source_ip='local',
                   session_id='environment:backup01', target_host='backup01')
        row.setdefault('metadata', {})['origin'] = 'unattributed'
    else:
        row['sensor'] = role
        row['target_host'] = {'portal': 'intranet01', 'forge': 'git01', 'cloud': 'cloud01', 'webedge':'support01', 'chatbot':'assistant01','broker':'assistant01'}[role]
        row['session_id'] = 'live:' + row['source_ip']
    return Event.model_validate(row)


class Sensors:
    def __init__(self, bus, root: Path, interface='wlan0', lab_ip='172.27.66.1'):
        self.bus, self.root, self.interface, self.lab_ip = bus, root, interface, lab_ip
        self.stop = threading.Event()
        self.status = {'logs': 'starting', 'capture': 'starting', 'dropped': 0}
        self.checkpoint = root / 'runtime/collector/sensor_offsets.json'
        self.offsets = json.loads(self.checkpoint.read_text()) if self.checkpoint.exists() else {}
        self.process = None
        self.seen_ports = {}
        self.last_signal = {}

    def emit(self, event):
        if not event:
            return
        # Throttle duplicated packet/audit signals, not SSH commands.
        if event.sensor not in {'cowrie', 'integrity'}:
            key = (event.source_ip, event.action, event.target)
            now = time.monotonic()
            if now - self.last_signal.get(key, -100) < 2:
                return
            self.last_signal[key] = now
            if len(self.last_signal) > 5000:
                self.last_signal = {k: v for k, v in self.last_signal.items() if now - v < 10}
        try:
            self.bus.queue.put_nowait(event)
        except queue.Full:
            self.status['dropped'] += 1

    def start(self):
        threading.Thread(target=self.logs, daemon=True).start()
        threading.Thread(target=self.capture, daemon=True).start()

    def logs(self):
        while not self.stop.wait(0.5):
            sources = [(self.root / 'runtime/cowrie/log/cowrie/cowrie.json', lambda x: cowrie_event(json.loads(x))),
                       (self.root / 'runtime/dc/files.log', smb_event), (self.root / 'runtime/dc/auth.json', domain_auth_event)]
            sources += [(self.root / f'runtime/{role}/events.jsonl', lambda x, role=role: target_log_event(x, role)) for role in ('portal', 'forge', 'cloud', 'linux','webedge','chatbot','broker')]
            sources.append((self.root / 'runtime/canary/events.jsonl', canary_event))
            for file, parser in sources:
                try:
                    stat = file.stat()
                    identity, offset = self.offsets.get(str(file), (stat.st_ino, 0))
                    if stat.st_ino != identity or stat.st_size < offset:
                        offset = 0
                    with file.open(encoding='utf-8', errors='replace') as stream:
                        stream.seek(offset)
                        for _ in range(200):
                            start = stream.tell()
                            line = stream.readline()
                            if not line or not line.endswith('\n'):
                                stream.seek(start)
                                break
                            try:
                                self.emit(parser(line))
                            except (ValueError, TypeError, KeyError):
                                self.status['logs'] = 'malformed line skipped'
                        self.offsets[str(file)] = (stat.st_ino, stream.tell())
                    self.bus.queue.join()
                    temporary = self.checkpoint.with_suffix('.tmp')
                    temporary.write_text(json.dumps(self.offsets))
                    temporary.replace(self.checkpoint)
                    self.status['logs'] = 'reading'
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    self.status['logs'] = type(exc).__name__

    def capture(self):
        fields = ['frame.time_epoch', 'ip.src', 'ip.dst', 'tcp.dstport', 'udp.dstport', 'tcp.flags.syn', 'tcp.flags.ack',
                  'ldap.protocolOp', 'ldap.AttributeDescription', 'kerberos.msg_type', 'kerberos.padata_type', 'kerberos.CNameString', 'srvsvc.opnum', 'ldap.assertionValue', 'ldap.attributeDesc']
        command = ['tshark', '-i', self.interface, '-l', '-n', '-f', 'dst net 172.27.66.0/24',
                   '-T', 'fields', '-E', 'separator=/t', '-E', 'occurrence=a']
        for field in fields:
            command += ['-e', field]
        try:
            errors = (self.root / 'runtime/collector/capture.log').open('a')
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors, text=True)
            self.status['capture'] = 'running'
            for line in self.process.stdout:
                if self.stop.is_set():
                    break
                self.wire_line(line)
            self.status['capture'] = 'stopped: ' + str(self.process.wait())
            errors.close()
        except (OSError, ValueError) as exc:
            self.status['capture'] = type(exc).__name__

    def wire_line(self, line: str):
        values = line.rstrip('\n').split('\t')
        if len(values) == 13:
            values += ['', '']
        if len(values) != 15:
            return
        stamp, source, dest, tcp, udp, syn, ack, ldap, attrs, krb, padata, user, srvsvc, assertion, attribute = values
        if dest not in {self.lab_ip, *['172.27.66.' + str(n) for n in (10,20,30,40,50,60,70,80)]} or not source or source == self.lab_ip or source.startswith('172.30.'):
            return
        timestamp = float(stamp)
        port = tcp or udp
        if dest == self.lab_ip and port in {'22', '8501', '8000'}:
            return
        host = 'backup01' if port in {'22', '2222'} else 'git01' if port == '3000' else 'intranet01' if port == '8088' else 'cloud01' if port == '9080' else 'services01' if port in {'2121', '1433', '3306', '3389', '6379', '27017'} else 'dc01'
        host = {'172.27.66.10': 'dc01', '172.27.66.20': 'backup01', '172.27.66.30': 'intranet01',
                '172.27.66.40': 'git01', '172.27.66.50': 'cloud01', '172.27.66.60': 'services01', '172.27.66.70':'assistant01','172.27.66.80':'support01'}.get(dest, host)
        base = dict(timestamp=timestamp, session_id='live:' + source, source_ip=source, sensor='wire', target_host=host)
        target_ports = {'22', '53', '80','88', '135', '139', '389', '445', '464', '636', '1053', '2222', '3000', '4566','8088', '9080', '3268', '3269', '2121', '1433', '3306', '3389', '6379', '27017'}
        if syn.casefold() in {'1', 'true'} and ack.casefold() in {'0', 'false'} and tcp in target_ports:
            ports = self.seen_ports.setdefault(source, {})
            ports[tcp] = timestamp
            self.seen_ports[source] = {p: t for p, t in ports.items() if timestamp - t <= 10}
            if len(self.seen_ports[source]) >= 3:
                self.emit(Event(**base, action='portscan'))
                self.seen_ports[source] = {}
        if '3' in ldap.split(','):
            classes = assertion.casefold().split(',')
            action = 'ldap_groups' if 'group' in classes else 'ldap_computers' if 'computer' in classes else 'ldap_users' if 'samaccountname' in attrs.casefold() or 'user' in classes else None
            if action:
                self.emit(Event(**base, action=action, metadata={'evidence': 'observed'}))
        if '15' in srvsvc.split(','):
            self.emit(Event(**base, action='enumerate_shares'))
        if '10' in krb.split(',') and '2' not in padata.split(',') and 'svc_backup' in user.casefold():
            self.emit(Event(**base, action='asrep_request', target='svc_backup', metadata={'assessment': 'Potential AS-REP roasting path; request without encrypted timestamp'}))

    def close(self):
        self.stop.set()
        if self.process and self.process.poll() is None:
            self.process.terminate()
