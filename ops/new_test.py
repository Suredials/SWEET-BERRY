"""Archive a capture and start fresh collectors without recreating lab targets."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def write_status(root: Path, document: dict) -> None:
    folder = root / 'runtime/control'
    folder.mkdir(parents=True, exist_ok=True)
    folder.chmod(0o755)
    temporary = folder / 'new-test.tmp'
    temporary.write_text(json.dumps(document, ensure_ascii=False), encoding='utf-8')
    temporary.chmod(0o644)  # No secrets: the dashboard reads this progress document.
    temporary.replace(folder / 'new-test.json')


def archive_capture(root: Path) -> dict:
    """Called with collectors stopped. Source logs remain mounted and readable."""
    from app.telemetry import Telemetry

    runtime = root / 'runtime'
    state_file = runtime / 'collector/state.json'
    prior = json.loads(state_file.read_text(encoding='utf-8')) if state_file.exists() else {}
    world = prior.get('world', {'domain': 'CORP.LOCAL', 'deception_level': 0, 'mutations': []})
    world['file_changes'] = []
    run_id = 'prueba-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:6]
    archive = runtime / 'archive' / run_id
    archive.mkdir(parents=True, exist_ok=False)
    archive.chmod(0o700)
    moved = []
    for name in ('collector', 'telemetry', 'network', 'pcap'):
        source = runtime / name
        if source.exists():
            source.rename(archive / name)
            moved.append(name)
        source.mkdir(parents=True, exist_ok=True)
    started = time.time()
    capture = {'run_id': run_id, 'started': started, 'archive': 'runtime/archive/' + run_id,
               'environment_preserved': True, 'archived_components': moved,
               'previous_sessions': len(prior.get('sessions', {})),
               'note': 'Nueva captura; objetivos, señuelos y conexiones existentes conservados. Los logs de origen mantienen su retención propia.'}
    (archive / 'manifest.json').write_text(json.dumps(capture, ensure_ascii=False, indent=2), encoding='utf-8')
    (runtime / 'collector/capture.json').write_text(json.dumps(capture), encoding='utf-8')
    (runtime / 'collector/state.json').write_text(json.dumps({'sessions': {}, 'world': world}), encoding='utf-8')
    # Start each parser at the current end; never import the previous test again.
    sources = [runtime / 'cowrie/log/cowrie/cowrie.json', runtime / 'dc/files.log', runtime / 'dc/auth.json']
    sources += [runtime / role / 'events.jsonl' for role in ('portal', 'forge', 'cloud', 'linux', 'canary', 'webedge', 'chatbot', 'broker')]
    offsets = {str(path): (path.stat().st_ino, path.stat().st_size) for path in sources if path.is_file()}
    (runtime / 'collector/sensor_offsets.json').write_text(json.dumps(offsets), encoding='utf-8')
    telemetry = Telemetry(root)
    try:
        for path, (inode, offset) in offsets.items():
            telemetry.set_cursor(path, inode, offset)
        old_index = archive / 'telemetry/index.sqlite'
        if old_index.exists():
            old = sqlite3.connect(old_index)
            try:
                canaries = old.execute('SELECT id,artifact,created,document FROM canaries').fetchall()
                telemetry.db.executemany('INSERT OR REPLACE INTO canaries VALUES (?,?,?,?)', canaries)
                telemetry.db.commit()
            finally:
                old.close()
    finally:
        telemetry.db.close()
    return capture


def main() -> int:
    import fcntl
    if os.geteuid() != 0 or ROOT.resolve() != Path('/home/suredials/sweetberry'):
        raise SystemExit('Use sudo on the reference Raspberry deployment.')
    control = ROOT / 'runtime/control'
    control.mkdir(parents=True, exist_ok=True)
    control.chmod(0o755)
    services = ['sweetberry-api', 'sweetberry-chat-broker', 'sweetberry-network-sensor', 'sweetberry-pcap']
    with (control / 'new-test.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        started = time.time()
        write_status(ROOT, {'state': 'running', 'started': started})
        result = {}
        error = None
        try:
            subprocess.run(['systemctl', 'stop', *services], check=True, timeout=45)
            result = archive_capture(ROOT)
        except Exception as exc:
            error = type(exc).__name__
        finally:
            try:
                subprocess.run(['systemctl', 'start', 'sweetberry-network-sensor'], check=True, timeout=30)
                subprocess.run(['systemctl', 'start', 'sweetberry-pcap',
                                'sweetberry-chat-broker', 'sweetberry-api'], check=True, timeout=60)
                import urllib.request
                for attempt in range(40):
                    try:
                        with urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=1):
                            break
                    except OSError:
                        if attempt == 39:
                            raise
                        time.sleep(.25)
            except Exception as exc:
                error = error or type(exc).__name__
        elapsed = round(time.time() - started, 1)
        write_status(ROOT, {**result, 'state': 'error' if error else 'done', 'error': error,
                            'finished': time.time(), 'elapsed_seconds': elapsed})
        print(json.dumps({'state': 'error' if error else 'done', 'elapsed_seconds': elapsed, **result}, ensure_ascii=False))
        return 1 if error else 0


if __name__ == '__main__':
    raise SystemExit(main())
