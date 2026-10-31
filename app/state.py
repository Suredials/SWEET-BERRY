import copy
import json
import threading
from pathlib import Path
from .detector import detect
from .llm_firewall import firewall
from .llm_reasoner import mock_reason
from .deception import plan_mutations
from .models import Event
from .behavior import profile_events


class Engine:
    def __init__(self, log: Path | None = None, actor=None):
        self.lock = threading.RLock()
        self.sessions: dict[str, dict] = {}
        self.log = log
        self.actor = actor
        self.world = {'domain': 'CORP.LOCAL', 'deception_level': 0, 'mutations': []}
        if log:
            log.parent.mkdir(parents=True, exist_ok=True)
            saved = log.with_name('state.json')
            if saved.exists():
                document = json.loads(saved.read_text(encoding='utf-8'))
                self.sessions = document['sessions']
                self.world = document['world']
                for session in self.sessions.values():session['profile']=profile_events(session['events'])

    def ingest(self, event: Event) -> dict:
        with self.lock:
            if event.sensor == 'integrity' and event.action == 'file_integrity_change':
                changes = self.world.setdefault('file_changes', [])
                changes.append(event.model_dump())
                self.world['file_changes'] = changes[-100:]
                self.write({'kind': 'integrity', **event.model_dump()})
                self.persist()
                return copy.deepcopy(self.world)
            if event.session_id not in self.sessions and len(self.sessions) >= 128:
                self.sessions.pop(next(iter(self.sessions)))
            state = self.sessions.setdefault(event.session_id, {'session_id': event.session_id, 'source_ip': event.source_ip,
                'domain': 'CORP.LOCAL', 'risk': 0, 'deception_level': 0, 'events': [], 'mutations': [], 'techniques': [],
                'mode': 'replay' if event.sensor == 'replay' else 'live', 'profile': {'likely_type': 'insufficient_evidence', 'confidence': 0}})
            scan = firewall(json.dumps({'target': event.target, 'metadata': event.metadata}, ensure_ascii=False))
            if event.sensor=='broker' and event.action=='chat_blocked':
                scan={'blocked':True,'reason':'llm_guard','risk':80}
            detection = detect('prompt_injection' if scan['blocked'] else event.action)
            if not scan['blocked'] and event.action == 'auth_failure':
                accounts = {e['target'] for e in state['events'] if e.get('original_action', e['action']) == 'auth_failure'
                            and e['target_host'] == event.target_host and 0 <= event.timestamp - e['timestamp'] <= 60 and e['target']}
                if event.target:
                    accounts.add(event.target)
                if len(accounts) >= 5:
                    detection = detect('password_spray_pattern')
            row = event.model_dump()
            row.update(detection)
            row['original_action'] = event.action
            state['sequence'] = state.get('sequence', 0) + 1
            row['sequence'] = state['sequence']
            row['firewall'] = scan
            if scan['blocked']:
                row['target'] = '[quarantined]'
            # Do not persist hostile raw input or authentication passwords.
            row['metadata'] = {'quarantined': True} if scan['blocked'] else {k: v for k, v in event.metadata.items() if k not in {'password', 'input', 'raw'}}
            state['events'].append(row)
            state['events'] = state['events'][-1000:]
            risk_key = detection['action'] + ':' + event.target_host
            seen = state.setdefault('scored_signals', [])
            awarded = detection['risk'] if risk_key not in seen else 0
            if awarded:
                seen.append(risk_key)
            row['base_risk'] = detection['risk']
            row['risk'] = awarded
            row['evidence'] = event.metadata.get('evidence', 'attempted' if event.sensor == 'cowrie' and event.action not in {'ssh_login', 'ssh_connect'} else 'observed')
            state['risk'] = min(100, state['risk'] + awarded)
            state['deception_level'] = max(state['deception_level'], detection['level'])
            if detection['mitre'] and detection['mitre'] not in state['techniques']:
                state['techniques'].append(detection['mitre'])
            live = self.actor and state['mode'] == 'live'
            registry = self.world['mutations'] if live else state['mutations']
            applied = {m['action'] for m in registry if m.get('ok')}
            for action in plan_mutations(detection['action'], state['deception_level']):
                if action not in applied:
                    mutation = self.actor(action) if self.actor and state['mode'] == 'live' else {'action': action, 'ok': True, 'simulated': True}
                    mutation['timestamp'] = event.timestamp
                    mutation['trigger'] = detection['action']
                    state['mutations'].append(mutation)
                    if live:
                        self.world['mutations'].append(copy.deepcopy(mutation))
                        if mutation.get('ok'):
                            self.world['deception_level'] = max(self.world['deception_level'], state['deception_level'])
                    self.write({'kind': 'mutation', 'session_id': event.session_id, **mutation})
            state['reasoner'] = mock_reason(state['events'], state['deception_level'])
            state['profile'] = profile_events(state['events'])
            self.write({'kind':'operator_profile','session_id':event.session_id,'source_ip':event.source_ip,
                        'timestamp':event.timestamp,'profile':state['profile']})
            self.write({'kind': 'event', **row})
            self.write({'kind': 'decision', 'session_id': event.session_id, **state['reasoner']})
            self.persist()
            return copy.deepcopy(state)

    def write(self, row: dict) -> None:
        if getattr(self, 'telemetry', None):
            mode = self.sessions.get(row.get('session_id'), {}).get('mode', 'live')
            self.telemetry.record({**row, 'mode': mode, 'sensor': row.get('sensor', 'engine'),
                                   'trust': 'deterministic-engine'})
        if self.log:
            with self.log.open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(row, ensure_ascii=False) + '\n')

    def persist(self):
        if self.log:
            saved = self.log.with_name('state.json')
            temporary = saved.with_suffix('.tmp')
            temporary.write_text(json.dumps({'sessions': self.sessions, 'world': self.world}), encoding='utf-8')
            temporary.replace(saved)

    def snapshot(self) -> dict:
        with self.lock:
            return copy.deepcopy(self.sessions)

    def clear_replays(self) -> None:
        with self.lock:
            self.sessions = {k: v for k, v in self.sessions.items() if v['mode'] != 'replay'}
            self.persist()
