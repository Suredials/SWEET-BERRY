"""Small functional lab services: portal, Git HTTP transport and object store."""
import datetime
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import threading
import time
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = Path('/srv/data')
ROLE = os.getenv('LURE_ROLE', 'portal')
HOST = {'portal': 'intranet01', 'forge': 'git01', 'cloud': 'cloud01'}[ROLE]
COMPANY = json.loads(Path('/opt/company.json').read_text())
LOCK = threading.Lock()


def seed():
    ROOT.mkdir(exist_ok=True)
    for name in ('documents', 'objects'):
        (ROOT / name).mkdir(exist_ok=True)
    (ROOT / 'documents/welcome.md').write_text('# Northstar Systems\nCORP.LOCAL employee services\nBackup operations: svc_backup\n')
    (ROOT / 'objects/backup-index.json').write_text(json.dumps({'project': 'cloud-migration', 'environment': 'lab', 'marker': COMPANY['lab_marker']}))
    if ROLE == 'forge' and not (ROOT / 'repos/backup-scripts.git').exists():
        work = ROOT / 'work'
        work.mkdir(exist_ok=True)
        (ROOT / 'repos').mkdir(exist_ok=True)
        subprocess.run(['git', 'init', '--bare', '--initial-branch=main', str(ROOT / 'repos/backup-scripts.git')], check=True, capture_output=True)
        subprocess.run(['git', '-C', str(work), 'init', '--initial-branch=main'], check=True, capture_output=True)
        for key, value in [('user.name', 'IT Operations'), ('user.email', 'operations@corp.local')]:
            subprocess.run(['git', '-C', str(work), 'config', key, value], check=True)
        (work / 'README.md').write_text('# Backup Operations\nDomain: CORP.LOCAL\nOwner: IT Operations\nHost: backup01\nAll credentials and data belong exclusively to the SweetBerry lab.\n')
        (work / 'backup.sh').write_text('# SWEETBERRY_CANARY_DECOY\n# Documentation only; no executable backup logic.\n')
        subprocess.run(['git', '-C', str(work), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(work), 'commit', '-m', 'Initial operations repository'], check=True, capture_output=True)
        subprocess.run(['git', '-C', str(work), 'push', str(ROOT / 'repos/backup-scripts.git'), 'main'], check=True, capture_output=True)


class Handler(BaseHTTPRequestHandler):
    server_version = 'Northstar-Services/1.0'

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *args):
        pass

    def record(self, action, target='', status=200, evidence='observed'):
        parsed = urlsplit(self.path)
        event = {'timestamp': time.time(), 'session_id': 'live:' + self.client_address[0],
                 'source_ip': self.client_address[0], 'sensor': ROLE, 'target_host': HOST,
                 'action': action, 'target': target[:256],
                 'metadata': {'method': self.command, 'http_status': status, 'evidence': evidence,
                              'input': (parsed.query + ' ' + self.headers.get('User-Agent', ''))[:4096]}}
        with LOCK:
            with Path('/var/log/lure/events.jsonl').open('a') as output:
                output.write(json.dumps(event) + '\n')

    def send(self, content, action=None, target='', status=200, mime='application/json', evidence='observed'):
        data = content if isinstance(content, bytes) else content.encode() if isinstance(content, str) else json.dumps(content).encode()
        if action:
            self.record(action, target, status, evidence)
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(data)

    def page(self, heading, body):
        self.send('<!doctype html><html><head><meta charset="utf-8"><title>Northstar Systems</title><style>body{font:16px system-ui;background:#f3f6fa;color:#19283c;max-width:960px;margin:60px auto;padding:24px}header{color:#3368a0;letter-spacing:3px}article{background:white;padding:32px;border:1px solid #dce4ef;border-radius:12px}a{color:#1761a6}li{margin:16px 0}code{background:#eef3f9;padding:5px}footer{color:#718096;font-size:12px;margin-top:30px}</style></head><body><header>NORTHSTAR SYSTEMS / '+HOST.upper()+'</header><h1>'+heading+'</h1><article>'+body+'</article><footer>CORP.LOCAL · Internal operations</footer></body></html>', mime='text/html; charset=utf-8')

    def do_GET(self):
        parsed = urlsplit(self.path)
        path = unquote(parsed.path)
        if path == '/health':
            return self.send({'status': 'ok', 'role': ROLE})
        if ROLE == 'forge' and path.startswith('/repos/backup-scripts.git/'):
            return self.git_request(parsed, path)
        if path == '/api/directory' and ROLE == 'portal':
            return self.send({'domain': COMPANY['domain'], 'employees': COMPANY['employees'], 'groups': COMPANY['groups']}, 'web_directory', 'directory', evidence='confirmed')
        if path == '/api/repos' and ROLE == 'forge':
            return self.send({'repositories': [{'name': 'backup-scripts', 'clone_url': 'http://' + self.headers.get('Host', 'git01:3000') + '/repos/backup-scripts.git'}]}, 'repo_discovery', 'backup-scripts', evidence='confirmed')
        if path == '/api/files' and ROLE == 'forge':
            return self.send({'files': sorted(p.name for p in (ROOT / 'work').iterdir() if p.is_file())}, 'repo_discovery', 'backup-scripts', evidence='confirmed')
        if path.startswith('/api/files/') and ROLE == 'forge':
            return self.artifact(ROOT / 'work', path[len('/api/files/'):], 'repo_read')
        if path == '/api/buckets' and ROLE == 'cloud':
            return self.send({'buckets': ['corp-backups'], 'region': 'lab-local-1'}, 'cloud_buckets', 'corp-backups', evidence='confirmed')
        if path == '/api/buckets/corp-backups/objects' and ROLE == 'cloud':
            return self.send({'objects': sorted(p.name for p in (ROOT / 'objects').iterdir() if p.is_file())}, 'cloud_objects', 'corp-backups', evidence='confirmed')
        if path.startswith('/api/buckets/corp-backups/objects/') and ROLE == 'cloud':
            name = path[len('/api/buckets/corp-backups/objects/'):]
            return self.artifact(ROOT / 'objects', name, 'cloud_inventory_read' if name == 'inventory.csv' else 'cloud_object_read')
        if path.startswith('/documents/') and ROLE == 'portal':
            return self.artifact(ROOT / 'documents', path[len('/documents/'):], 'web_document_read')
        if path in {'/admin', '/login'}:
            self.record('web_admin_access', path, 200)
            return self.page('Operations login', '<form method="post" action="/login"><p><input name="username" placeholder="Domain user"></p><p><input name="password" type="password" placeholder="Password"></p><button>Sign in</button></form>')
        if path == '/':
            self.record('web_visit', ROLE)
            docs = ''.join('<li><a href="/documents/'+html.escape(p.name)+'">'+html.escape(p.name)+'</a></li>' for p in (ROOT / 'documents').iterdir() if p.is_file())
            if ROLE == 'portal':
                return self.page('Employee services', '<p>Welcome to Northstar Systems internal operations.</p><ul><li><a href="/api/directory">Employee directory</a></li><li><a href="'+html.escape(os.getenv('FORGE_URL', 'http://172.27.66.40:3000'))+'">Engineering repositories</a></li>'+docs+'</ul><a href="/login">Operations login</a>')
            if ROLE == 'forge':
                return self.page('Engineering / repositories', '<p><a href="/api/repos">Repository catalog</a> · <a href="/api/files">Browse files</a></p><code>git clone http://'+html.escape(self.headers.get('Host', 'git01:3000'))+'/repos/backup-scripts.git</code>')
            return self.page('Cloud object storage', '<p>Region: lab-local-1</p><a href="/api/buckets">List buckets</a> · <a href="/api/buckets/corp-backups/objects">Browse corp-backups</a>')
        self.send({'error': 'Not found'}, 'web_not_found', path, 404)

    def artifact(self, root, name, action):
        if not name or '/' in name or '\\' in name or name.startswith('.') or len(name) > 128:
            return self.send({'error': 'Invalid artifact'}, 'web_not_found', name, 404)
        file = root / name
        if not file.is_file():
            return self.send({'error': 'Not found'}, 'web_not_found', name, 404)
        if name == 'cloud_credentials.txt':
            action = 'secret_access'
        self.send(file.read_bytes(), action, name, mime='text/plain; charset=utf-8', evidence='confirmed')

    def do_POST(self):
        if ROLE == 'forge' and urlsplit(self.path).path == '/repos/backup-scripts.git/git-upload-pack':
            return self.git_request(urlsplit(self.path), urlsplit(self.path).path)
        length = int(self.headers.get('Content-Length', '0'))
        if length > 4096:
            return self.send({'error': 'Too large'}, status=413)
        # Passwords are discarded, never written to logs.
        self.rfile.read(length)
        self.send({'error': 'Authentication unavailable for this account'}, 'web_auth_failure', '/login', 401, evidence='attempted')

    def git_request(self, parsed, path):
        suffix = path[len('/repos/backup-scripts.git/'):]
        if suffix not in {'info/refs', 'git-upload-pack', 'HEAD'} or 'git-receive-pack' in parsed.query:
            return self.send({'error': 'Read-only repository'}, status=403)
        length = int(self.headers.get('Content-Length', '0'))
        if length > 65536:
            return self.send({'error': 'Too large'}, status=413)
        env = dict(os.environ, GIT_PROJECT_ROOT=str(ROOT / 'repos'), GIT_HTTP_EXPORT_ALL='1',
                   PATH_INFO=path[len('/repos'):], QUERY_STRING=parsed.query, REQUEST_METHOD=self.command,
                   CONTENT_TYPE=self.headers.get('Content-Type', ''), CONTENT_LENGTH=str(length), REMOTE_ADDR=self.client_address[0])
        if self.headers.get('Git-Protocol'):
            env['HTTP_GIT_PROTOCOL'] = self.headers['Git-Protocol']
        result = subprocess.run(['git', 'http-backend'], input=self.rfile.read(length), capture_output=True, env=env, timeout=15)
        if result.returncode:
            return self.send({'error': 'Git transport unavailable'}, status=503)
        header, _, body = result.stdout.partition(b'\r\n\r\n')
        if not body:
            header, _, body = result.stdout.partition(b'\n\n')
        self.record('repo_read' if suffix == 'git-upload-pack' else 'repo_discovery', 'backup-scripts', evidence='confirmed')
        self.send_response(200)
        for line in header.decode().splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                if key.lower() != 'status':
                    self.send_header(key, value.strip())
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    seed()
    server = ThreadingHTTPServer(('0.0.0.0', 8080), Handler)
    server.request_queue_size = 32
    print('Ready:', ROLE, flush=True)
    server.serve_forever()
