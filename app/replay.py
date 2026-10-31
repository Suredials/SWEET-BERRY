import json
from pathlib import Path
from .models import Event

SCENARIOS = Path(__file__).resolve().parents[1] / 'scenarios'
CATALOG = [
    {'id': 'replay_full_attack', 'name': 'Classic identity trail', 'family': 'IDENTITY', 'description': 'Offline potential AS-REP storyline, shares and canaries.'},
    {'id': 'domain_recon', 'name': 'Inside the directory', 'family': 'IDENTITY', 'description': 'Users, groups, computers and Finance$ breadcrumbs.'},
    {'id': 'linux_operator', 'name': 'The backup operator', 'family': 'LINUX', 'description': 'SSH discovery, real file routes and the canary trail.'},
    {'id': 'devops_pivot', 'name': 'Code to cloud', 'family': 'DEVOPS', 'description': 'Portal, repository, migration map and object storage.'},
    {'id': 'cloud_trail', 'name': 'Follow the objects', 'family': 'CLOUD', 'description': 'Buckets, inventory and planted cloud credentials.'},
    {'id': 'prompt_guard', 'name': 'Behind the guardrail', 'family': 'AI SECURITY', 'description': 'Benign context followed by quarantined instruction attempts.'},
    {'id': 'multi_vector', 'name': 'Three operators', 'family': 'CAMPAIGN', 'description': 'Concurrent-looking identity, DevOps and Linux paths from three sources.'},
    {'id': 'authentication_pattern', 'name': 'The authentication pattern', 'family': 'AUTHENTICATION', 'description': 'Offline failure fixtures reveal a possible spray pattern. No login requests are sent.'},
    {'id': 'service_sweep', 'name': 'Across the service surface', 'family': 'NETWORK', 'description': 'Protocol contacts and discovery across database and infrastructure façades.'},
    {'id': 'demo_asrep', 'name': 'Identity excerpt', 'family': 'EXCERPT', 'description': 'Synthetic Kerberos sequence only.'},
    {'id': 'demo_smb', 'name': 'Shares excerpt', 'family': 'EXCERPT', 'description': 'Synthetic share and backup discovery.'},
    {'id': 'demo_cloud', 'name': 'Canary excerpt', 'family': 'EXCERPT', 'description': 'Synthetic cloud canary interaction.'},
]


def scenario_events(name='replay_full_attack') -> list[Event]:
    if name not in {row['id'] for row in CATALOG}:
        raise ValueError('Unknown scenario')
    rows = json.loads((SCENARIOS / (name + '.json')).read_text())
    events = []
    for i, row in enumerate(rows):
        row = dict(row)
        actor = row.pop('actor', '42')
        session = 'replay-001' if name == 'replay_full_attack' else 'replay-' + name + '-' + actor
        events.append(Event(timestamp=1761910000 + i * 0.5, session_id=session, source_ip='192.0.2.' + actor, sensor='replay', **row))
    return events


def run_scenario(engine, name='replay_full_attack') -> dict:
    result = {}
    for event in scenario_events(name):
        result = engine.ingest(event)
    return result
