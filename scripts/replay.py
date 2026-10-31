import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.state import Engine
from app.replay import run_scenario

name = Path(sys.argv[1]).stem if len(sys.argv) > 1 else 'replay_full_attack'
engine = Engine()
run_scenario(engine, name)
sessions = list(engine.snapshot().values())
events = sorted([event for session in sessions for event in session['events']], key=lambda event: event['timestamp'])
for event in events:
    print(f"[EVENT] {event['source_ip']} {event['name']} {event['mitre'] or ''}")
for session in sessions:
    for mutation in session['mutations']:
        print('[DECEPTION]', session['source_ip'], mutation['action'], '(replay)')
print(json.dumps({'sessions': len(sessions), 'events': len(events), 'risk': max(session['risk'] for session in sessions),
                  'deception_level': max(session['deception_level'] for session in sessions),
                  'techniques': sorted({technique for session in sessions for technique in session['techniques']})}, indent=2))
