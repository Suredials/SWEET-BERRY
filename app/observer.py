"""Host-side syscall observations, independent of writable target logs.

Records executable paths and IPv4/IPv6 connect attempts, never argv or file contents.
This is a lightweight observer, not a complete kernel audit facility.
"""
import copy
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import threading
import time


class TraceAssembler:
    """Join interleaved strace unfinished/resumed calls without losing attempts."""
    def __init__(self):self.pending={}
    def feed(self,line):
        match=re.match(r'(?:\[pid\s+)?(\d+)\]?\s+\d+\.\d+\s+',line)
        pid=match[1] if match else 'single'
        resumed=re.search(r'<\.\.\. (\w+) resumed>(.*)',line)
        if resumed:
            start=self.pending.pop((pid,resumed[1]),None)
            return start+resumed[2]+'\n' if start else ''
        if '<unfinished ...>' in line:
            call=re.search(r'\b(\w+)\(',line[match.end():] if match else line)
            if call:self.pending[(pid,call[1])]=line.split('<unfinished ...>',1)[0]
        if len(self.pending)>1000:self.pending.clear()
        return line


def parse_trace(line: str, role: str) -> dict | None:
    match = re.search(r'(\d+\.\d+)\s+(execveat|execve|connect|getsockname|accept4?|openat2?|renameat2?|rename|unlinkat|unlink|mkdirat|mkdir|rmdir|clone3?|fork|vfork|exit_group|exit)\((.*)', line)
    if not match:
        return None
    stamp, call, detail = match.groups()
    pid = re.search(r'(?:\[pid\s+)?(\d+)\]?\s+$', line[:match.start()])
    row = {'timestamp': float(stamp), 'container': role, 'sensor': 'host-strace',
           'syscall':call,
           'pid': int(pid[1]) if pid else None, 'attribution': 'container only',
           'syscall_phase':'incomplete' if '<unfinished ...>' in detail else 'complete'}
    if call in {'execve','execveat'}:
        executable = re.search(r'"([^"\n]{1,512})"', detail)
        if not executable:
            return None
        row.update(kind='process_exec', executable=executable[1],
                   result='failed' if re.search(r'= -1\b', detail) else 'observed')
        preview=detail[detail.find('['):detail.rfind(']')+1][:2048]
        preview=re.sub(r'(?i)(Bearer\s+)[^\s"\\,]+',r'\1[redacted]',preview)
        preview=re.sub(r'(?i)((?:password|passwd|token|secret|api_key)[=: ]+)[^\s"\\,]+',r'\1[redacted]',preview)
        preview=re.sub(r'(?i)("--?(?:password|passwd|token|secret|api[-_]key)"\s*,\s*")[^"]*',r'\1[redacted]',preview)
        preview=re.sub(r'(?i)([A-Z0-9_]*(?:PASSWORD|TOKEN|SECRET|API_KEY)[A-Z0-9_]*=)[^\s"\\,]+',r'\1[redacted]',preview)
        row['argv_preview']=preview
    elif call in {'clone','clone3','fork','vfork'}:
        child=re.search(r"= (\d+)(?: /\* (\d+) in strace's PID NS \*/)?\s*$",detail)
        if not child or int(child[1])<=0:return None
        row.update(kind='process_fork',child_pid=int(child[2] or child[1]),namespace_child_pid=int(child[1]),result='observed')
    elif call in {'exit','exit_group'}:
        row.update(kind='process_exit',result=detail[:30])
    elif call in {'openat','openat2'}:
        path = re.match(r'[^,]+, "([^"\n]{1,512})", (.*)', detail)
        if not path:
            return None
        writing=bool(re.search(r'O_WRONLY|O_RDWR',path[2]))
        row.update(kind='file_write_open' if writing else 'file_open',path=path[1],
                   result='failed' if re.search(r'= -1\b', detail) else 'opened for writing; not proof of completed write' if writing else 'opened for reading')
        if not writing and (path[1] in {'/etc/passwd','/etc/shadow','/srv/corp/operations.txt'} or '/.ssh/' in path[1] or '/.aws/' in path[1]):row['kind']='sensitive_path_open'
    elif call in {'rename','renameat','renameat2','unlink','unlinkat','mkdir','mkdirat','rmdir'}:
        row.update(kind='file_'+call,paths=re.findall(r'"([^"\n]{1,512})"',detail),
                   result='failed' if re.search(r'= -1\b',detail) else 'observed')
    else:
        address = re.search(r'(?:inet_addr\("|inet_pton\(AF_INET6, ")([0-9a-fA-F:.]+)"', detail)
        port = re.search(r'(?:sin_port|sin6_port)=htons\((\d+)\)', detail)
        if not address or not port:
            return None
        try:
            ip = ipaddress.ip_address(address[1])
        except ValueError:
            return None
        outcome = re.search(r'= (-?\d+)(?: (\w+))?', detail)
        row.update(kind='network_accept' if call.startswith('accept') else 'network_connect', destination=str(ip), port=int(port[1]),
                   scope='private' if ip.is_private else 'public',
                   result=(outcome[2] or outcome[1]) if outcome else 'unfinished',
                   assessment='connection attempt; not evidence of C2', egress_policy='external egress denied')
        descriptor=re.match(r'(\d+),',detail)
        if descriptor:row['socket_fd']=int(descriptor[1])
        if call=='getsockname':row.update(kind='network_local',local_address=str(ip),local_port=int(port[1]))
    return row


class Observer:
    def __init__(self, root: Path, live: bool = False, telemetry=None):
        self.root, self.live = root, live
        try:self.boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        except OSError:self.boot_id='offline'
        self.telemetry = telemetry
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.processes = []
        self.rows = []
        self.sequence = 0
        self.status = {'mode': 'host-side' if live else 'offline', 'linux': 'starting' if live else 'offline'}
        self.log = root / 'runtime/collector/observer.jsonl'
        if self.log.exists():
            try:
                with self.log.open('rb') as stream:
                    start = max(0, self.log.stat().st_size - 1024 * 1024)
                    stream.seek(start)
                    if start:
                        stream.readline()
                    for line in stream:
                        self.rows.append(json.loads(line))
                self.rows = self.rows[-300:]
                self.sequence = max((r.get('id', 0) for r in self.rows), default=0)
            except (OSError, ValueError):
                self.rows = []

    def record(self, row):
        with self.lock:
            self.sequence += 1
            row['id'] = self.sequence
            if self.telemetry:
                indexed=self.telemetry.record({**row,'trust':'host-syscall','asset':row.get('container','unknown')})
                row['event_id']=indexed['event_id']
            self.rows.append(row)
            self.rows = self.rows[-1500:]
            self.log.parent.mkdir(parents=True, exist_ok=True)
            if self.log.exists() and self.log.stat().st_size > 10 * 1024 * 1024:
                self.log.replace(self.log.with_suffix('.previous.jsonl'))
            with self.log.open('a') as stream:
                stream.write(json.dumps(row) + '\n')

    def snapshot(self):
        with self.lock:
            recent=[r for r in self.rows if r['kind'] not in {'file_open','process_exit'}][-150:]
            return {'status': dict(self.status), 'sequence': self.sequence, 'events': copy.deepcopy(recent),
                    'limitations': 'Host-side syscall tracing of attached target processes and descendants. Read-open events remain in the telemetry index. Encrypted payloads and processes that end before attachment can be missed. No automatic C2 attribution.'}

    def start(self):
        if self.live:
            for role in ('linux','dc','forge','cloud','portal','canary','chatbot','webtrap','webedge'):
                self.status[role]='starting'
                threading.Thread(target=self.watch,args=(role,),daemon=True,name='observer-'+role).start()

    def watch(self,role='linux'):
        while not self.stop.is_set():
            process = None
            try:
                result = subprocess.run(['docker', 'compose', 'ps', '-q', role], cwd=self.root,
                                        capture_output=True, text=True, timeout=5, check=True)
                cid = result.stdout.strip()
                if not re.fullmatch(r'[0-9a-f]{12,64}', cid):
                    raise ValueError('Container unavailable')
                result = subprocess.run(['docker', 'top', cid, '-eo', 'pid'], capture_output=True,
                                        text=True, timeout=5, check=True)
                pids = [p.strip() for p in result.stdout.splitlines()[1:] if p.strip().isdigit()]
                if not pids:
                    raise ValueError('No target processes')
                command = ['strace', '-f', '-qq', '-ttt', '--decode-pids=pidns', '-o', '/dev/stderr', '-s', '1024', '-e', 'trace=execve,execveat,connect,getsockname,accept,accept4,openat,openat2,rename,renameat,renameat2,unlink,unlinkat,mkdir,mkdirat,rmdir,clone,clone3,fork,vfork,exit,exit_group']
                for pid in pids:
                    command += ['-p', pid]
                process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                           text=True, bufsize=1)
                self.processes.append(process)
                self.status[role] = 'attached'
                process_keys={}
                parents={}
                def identity(pid):
                    try:start=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19]
                    except (OSError,IndexError):start=process_keys.get(pid,':'+str(time.time_ns())).rsplit(':',1)[-1]
                    if pid not in process_keys or process_keys[pid].rsplit(':',1)[-1]!=start:
                        process_keys[pid]=self.boot_id+':'+cid[:12]+':'+str(pid)+':'+start
                    return process_keys[pid]
                if self.telemetry:
                    self.telemetry.correlator.register_target(cid,role,identity(int(pids[0])))
                    self.telemetry.record({'sensor':'host-strace','asset':role,'kind':'observer_attached',
                        'container_id':cid,'init_process_key':identity(int(pids[0])),'trust':'host-syscall'})
                assembler=TraceAssembler()
                for line in process.stderr:
                    if self.stop.is_set():
                        break
                    row = parse_trace(assembler.feed(line), role)
                    if row:
                        row['container_id']=cid
                        if row.get('pid'):
                            try:row['process_name']=Path(f'/proc/{row["pid"]}/exe').readlink().name
                            except OSError:pass
                            row['process_key']=identity(row['pid'])
                            row['parent_process_key']=parents.get(row['pid'])
                            if row.get('child_pid'):
                                parents[row['child_pid']]=row['process_key']
                                row['child_process_key']=identity(row['child_pid'])
                        self.record(row)
                self.status[role] = 'detached; retrying'
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                self.status[role] = type(exc).__name__
            finally:
                if process and process.poll() is None:
                    process.terminate()
                if process in self.processes:
                    self.processes.remove(process)
            self.stop.wait(5)

    def close(self):
        self.stop.set()
        for process in list(self.processes):
            if process.poll() is None:
                process.terminate()
