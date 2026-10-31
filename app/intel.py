"""Local observations and inventory; no invented external reputation feed."""
import ipaddress
import json
from pathlib import Path
import subprocess
import threading
import time
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
ASSETS = [
    {'id':'dns','name':'DNS sink','role':'Local lab resolution / outbound DNS evidence','zone':'SENSOR','ports':'private DNS 53','kind':'DNS sink / no Internet forwarding','address':'internal'},
    {'id':'chatbot','name':'assistant01','role':'Corporate assistant / read-only tools','zone':'AI DEFENSE','ports':'80','kind':'Guarded chatbot','address':'172.27.66.70'},
    {'id':'webtrap','name':'support01','role':'Deliberately vulnerable upload portal','zone':'WEB LAB','ports':'80 via evidence gateway','kind':'Unprivileged PHP container','address':'172.27.66.80'},
    {'id':'guard','name':'LLM Guard','role':'Input/output scanners','zone':'SENSOR','ports':'private','kind':'Protect AI / CPU classifier','address':'internal'},
    {'id':'webedge','name':'Support gateway','role':'Independent HTTP evidence / quarantine','zone':'SENSOR','ports':'proxy to support01','kind':'Evidence gateway','address':'internal'},
    {'id':'forge-edge','name':'Git gateway','role':'Git HTTP request evidence','zone':'SENSOR','ports':'proxy to git01','kind':'Evidence gateway','address':'internal'},
    {'id':'cloud-edge','name':'AWS gateway','role':'AWS request evidence / read-only policy','zone':'SENSOR','ports':'proxy to Moto','kind':'Evidence gateway','address':'internal'},
    {'id': 'dc', 'name': 'DC01', 'role': 'Identity / domain controller', 'zone': 'IDENTITY', 'ports': '88 · 389 · 445 · 1053', 'kind': 'Samba AD', 'address': '172.27.66.10'},
    {'id': 'linux', 'name': 'backup01', 'role': 'Linux backup host', 'zone': 'OPERATIONS', 'ports': 'SSH :22', 'kind': 'Real Linux', 'address': '172.27.66.20'},
    {'id': 'cowrie', 'name': 'SSH gateway', 'role': 'Session recording / proxy', 'zone': 'SENSOR', 'ports': 'proxy to backup01', 'kind': 'Cowrie proxy', 'address': 'internal'},
    {'id': 'portal', 'name': 'intranet01', 'role': 'Employee portal / documents', 'zone': 'BUSINESS', 'ports': '8088', 'kind': 'Lab portal', 'address': '172.27.66.30'},
    {'id': 'forge', 'name': 'git01', 'role': 'Engineering repositories / issues', 'zone': 'DEVOPS', 'ports': '3000', 'kind': 'Gitea', 'address': '172.27.66.40'},
    {'id': 'cloud', 'name': 'cloud01', 'role': 'S3 / IAM / STS / cloud canaries', 'zone': 'CLOUD LAB', 'ports': '4566 / 9080', 'kind': 'Moto AWS emulator','address':'172.27.66.50'},
    {'id': 'canary', 'name': 'services01', 'role': 'FTP / SQL / Redis / RDP / MongoDB', 'zone': 'PROTOCOL LURES', 'ports': '2121 · 1433 · 3306 · 3389 · 6379 · 27017', 'kind': 'OpenCanary façades', 'address': '172.27.66.60'},
]


class Inventory:
    def __init__(self, live=False):
        self.live = live
        self.lock = threading.Lock()
        self.cached = []
        self.checked = 0

    def snapshot(self):
        with self.lock:
            if time.monotonic() - self.checked < 10 and self.cached:
                return self.cached
            containers = {}
            if self.live:
                try:
                    result = subprocess.run(['docker', 'compose', 'ps', '--all', '--format', 'json'], cwd=ROOT, capture_output=True, text=True, timeout=3)
                    for line in result.stdout.splitlines():
                        row = json.loads(line)
                        containers[row['Service']] = {'status': row.get('State', 'unknown'), 'health': row.get('Health', '')}
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    pass
            self.cached = [{**asset, **containers.get(asset['id'], {'status': 'unknown' if self.live else 'offline', 'health': ''})} for asset in ASSETS]
            self.checked = time.monotonic()
            return self.cached


def local_intelligence(sessions):
    sources = {}
    techniques = {}
    for session in sessions.values():
        source = session['source_ip']
        try:
            private = ipaddress.ip_address(source).is_private
        except ValueError:
            private = False
        item = sources.setdefault(source, {'source_ip': source, 'scope': 'private / laboratory' if private else 'unverified address',
            'sessions': 0, 'events': 0, 'risk': 0, 'hosts': [], 'techniques': [], 'canary_hits': 0, 'firewall_blocks': 0, 'mode': session['mode']})
        item['sessions'] += 1
        item['events'] += len(session['events'])
        item['risk'] = max(item['risk'], session['risk'])
        for event in session['events']:
            if event['target_host'] not in item['hosts']:
                item['hosts'].append(event['target_host'])
            if event.get('mitre'):
                techniques.setdefault(event['mitre'], {'id': event['mitre'], 'name': event['name'], 'count': 0})['count'] += 1
                if event['mitre'] not in item['techniques']:
                    item['techniques'].append(event['mitre'])
            item['canary_hits'] += event['action'] == 'secret_access'
            item['firewall_blocks'] += bool(event.get('firewall', {}).get('blocked'))
    return {'provenance': 'Local sensor observations only. No external reputation or actor attribution.',
            'sources': sorted(sources.values(), key=lambda x: x['risk'], reverse=True),
            'techniques': sorted(techniques.values(), key=lambda x: x['count'], reverse=True)}


def transcripts(root=ROOT, since: float = 0):
    file = root / 'runtime/cowrie/log/cowrie/cowrie.json'
    if not file.exists():
        return []
    output = []
    try:
        with file.open('rb') as stream:
            start = max(0, file.stat().st_size - 1024 * 1024)
            stream.seek(start)
            if start:
                stream.readline()
            for line in stream:
                try:
                    row = json.loads(line)
                    if row.get('eventid') == 'cowrie.command.input':
                        if since:
                            try:
                                if datetime.fromisoformat(str(row.get('timestamp', '')).replace('Z', '+00:00')).timestamp() < since:
                                    continue
                            except ValueError:
                                continue
                        output.append({'timestamp': row.get('timestamp'), 'session': row.get('session'),
                                       'source_ip': row.get('src_ip'), 'command': str(row.get('input', ''))[:4096]})
                except ValueError:
                    continue
    except OSError:
        return []
    return output[-150:]
