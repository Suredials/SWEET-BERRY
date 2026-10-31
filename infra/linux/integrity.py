"""Bounded file metadata monitor, running as the unprivileged lab user."""
import hashlib
import json
from pathlib import Path
import time

ROOTS = [Path('/srv/corp'), Path('/home/analyst')]
LOG = Path('/var/log/integrity/events.jsonl')


def snapshot():
    files = {}
    for root in ROOTS:
        for path in root.rglob('*'):
            if len(files) >= 200:
                break
            try:
                if path.is_symlink() or not path.is_file() or '.cache' in path.parts or '.ssh' in path.parts:
                    continue
                stat = path.stat()
                with path.open('rb') as stream:
                    digest = hashlib.sha256(stream.read(65536)).hexdigest()
                files[str(path)[:256]] = {'sha256_prefix64k': digest, 'size': stat.st_size, 'mtime_ns': stat.st_mtime_ns}
            except (OSError, ValueError):
                continue
    return files


previous = snapshot()
while True:
    time.sleep(1)
    current = snapshot()
    for path in sorted(set(current) | set(previous)):
        if current.get(path) == previous.get(path):
            continue
        change = 'created' if path not in previous else 'deleted' if path not in current else 'modified'
        event = {'timestamp': time.time(), 'session_id': 'environment:backup01', 'source_ip': 'local', 'sensor': 'integrity',
                 'target_host': 'backup01', 'action': 'file_integrity_change', 'target': path,
                 'metadata': {'change': change, 'origin': 'unattributed', 'evidence': 'confirmed',
                              'previous': previous.get(path), 'current': current.get(path)}}
        try:
            with LOG.open('a') as output:
                output.write(json.dumps(event) + '\n')
        except OSError:
            pass
    previous = current
