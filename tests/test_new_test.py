import json
from pathlib import Path
from app.evidence_reader import EvidenceReader
from app.intel import transcripts
from app.telemetry import Telemetry
from ops.new_test import archive_capture


def test_quick_capture_preserves_evidence_and_world_without_reimport(tmp_path):
    collector = tmp_path / 'runtime/collector'
    collector.mkdir(parents=True)
    world = {'domain': 'CORP.LOCAL', 'deception_level': 4,
             'mutations': [{'action': 'expose_cloud_credential', 'ok': True}], 'file_changes': [1]}
    (collector / 'state.json').write_text(json.dumps({'sessions': {'old': {'risk': 70}}, 'world': world}))
    (collector / 'events.jsonl').write_text('previous evidence\n')
    source = tmp_path / 'runtime/portal/events.jsonl'
    source.parent.mkdir(parents=True)
    source.write_text(json.dumps({'timestamp': 1, 'action': 'web_visit'}) + '\n')
    old = Telemetry(tmp_path)
    old.record({'event_id': 'old-evidence', 'kind': 'web_visit'})
    old.db.execute('INSERT INTO canaries VALUES (?,?,?,?)', ('canary-1', 'artifact', 1, '{}'))
    old.db.commit()
    old.db.close()

    result = archive_capture(tmp_path)
    archive = tmp_path / result['archive']
    assert (archive / 'collector/events.jsonl').read_text() == 'previous evidence\n'
    assert (archive / 'telemetry/index.sqlite').exists()
    state = json.loads((collector / 'state.json').read_text())
    assert state['sessions'] == {}
    assert state['world']['deception_level'] == 4
    assert state['world']['mutations'] == world['mutations']
    assert state['world']['file_changes'] == []
    fresh = Telemetry(tmp_path)
    assert fresh.query(mode='') == []
    assert fresh.db.execute('SELECT id FROM canaries').fetchone()[0] == 'canary-1'
    reader = EvidenceReader(tmp_path, fresh)
    reader.read('portal', 'portal', source)
    assert fresh.query(mode='') == []  # Previous source records are not reimported.
    with source.open('a') as stream:
        stream.write(json.dumps({'timestamp': 2, 'action': 'new_interaction'}) + '\n')
    reader.read('portal', 'portal', source)
    assert len(fresh.query(mode='')) == 1
    fresh.db.close()


def test_transcript_uses_current_capture_boundary(tmp_path):
    file = tmp_path / 'runtime/cowrie/log/cowrie/cowrie.json'
    file.parent.mkdir(parents=True)
    rows = [{'eventid': 'cowrie.command.input', 'timestamp': stamp, 'input': command}
            for stamp, command in [('2026-01-01T00:00:00Z', 'old'), ('2026-01-02T00:00:00Z', 'new')]]
    file.write_text(''.join(json.dumps(row) + '\n' for row in rows))
    assert [r['command'] for r in transcripts(tmp_path, since=1767312000)] == ['new']
