import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = {1: 'expose_users', 3: 'expose_backup_share', 4: 'expose_cloud_credential'}
BRANCHES = {
    'ldap_groups': ['expose_finance_share'],
    'ldap_computers': ['expose_sql_note'],
    'web_directory': ['expose_it_runbook'],
    'repo_discovery': ['expose_repository_notes'],
    'repo_read': ['expose_cloud_map'],
    'cloud_buckets': ['expose_cloud_inventory'],
    'cloud_inventory_read': ['expose_cloud_credential'],
    'system_discovery': ['expose_it_runbook'],
}


def plan_mutations(action, level):
    return list(dict.fromkeys([name for threshold, name in MUTATIONS.items() if threshold <= level] + BRANCHES.get(action, [])))


def apply_mutation(action: str) -> dict:
    allowed = set(MUTATIONS.values()) | {item for branch in BRANCHES.values() for item in branch}
    if action not in allowed:
        raise ValueError('Unsupported mutation')
    commands = []
    if action in {*MUTATIONS.values(), 'expose_finance_share', 'expose_sql_note'}:
        commands.append(['docker', 'compose', 'exec', '-T', 'dc', 'python3', '/opt/sweetberry/mutate.py', action])
    scripts = {
        'expose_users': "from pathlib import Path; Path('/srv/corp/users.txt').write_text('administrator\\nsvc_backup\\nanalyst\\n')",
        'expose_backup_share': "from pathlib import Path; p=Path('/srv/corp/Backups'); p.mkdir(exist_ok=True); (p/'inventory.csv').write_text('host,role\\ndc01,dc\\nbackup01,backup\\n'); (p/'backup.ps1').write_text('# SWEETBERRY_CANARY_DECOY inert backup documentation\\n')",
        'expose_cloud_credential': "from pathlib import Path; p=Path('/srv/corp/Backups'); p.mkdir(exist_ok=True); (p/'cloud_credentials.txt').write_text('AWS_ACCESS_KEY_ID=SWEETBERRY_CANARY_DECOY_NOT_VALID\\nAWS_SECRET_ACCESS_KEY=SWEETBERRY_CANARY_DECOY_NOT_VALID\\n')",
        'expose_it_runbook': "from pathlib import Path; Path('/srv/corp/it-runbook.md').write_text('# IT Operations\\nRepository: git01:3000/repos/backup-scripts.git\\nObject storage: cloud01:9080\\nSWEETBERRY_CANARY_DECOY\\n')",
    }
    if action in scripts:
        commands.append(['docker', 'compose', 'exec', '-T', '--user', 'analyst', 'linux', 'python3', '-c', scripts[action]])
    services = {'expose_it_runbook': ['portal'], 'expose_finance_share': ['portal'],
                'expose_repository_notes': ['forge'], 'expose_cloud_map': ['forge', 'portal'],
                'expose_cloud_inventory': ['cloud'], 'expose_cloud_credential': ['cloud']}
    for service in services.get(action, []):
        if service in {'forge','cloud'}:
            continue
        commands.append(['docker', 'compose', 'exec', '-T', service, 'python3', '/opt/cloud/seed.py' if service=='cloud' else '/opt/lures/mutate.py', action])
    results = []
    if 'forge' in services.get(action,[]):
        try:
            from .lab_services import mutate_gitea
            results.append(mutate_gitea(action))
        except Exception as exc:
            results.append({'host':'git01','ok':False,'detail':type(exc).__name__})
    if 'cloud' in services.get(action,[]):
        try:
            from .lab_services import mutate_cloud
            results.append(mutate_cloud(action))
        except Exception as exc:results.append({'host':'cloud01','ok':False,'detail':type(exc).__name__})
    for command in commands:
        try:
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=15)
            host = next((name for service, name in [('dc', 'dc01'), ('linux', 'backup01'), ('portal', 'intranet01'), ('forge', 'git01'), ('cloud', 'cloud01')] if service in command), 'unknown')
            results.append({'host': host, 'ok': result.returncode == 0,
                            'detail': (result.stdout if result.returncode == 0 else result.stderr)[-1500:]})
        except (OSError, subprocess.TimeoutExpired) as exc:
            results.append({'host': 'dc01' if 'dc' in command else 'backup01', 'ok': False, 'detail': type(exc).__name__})
    return {'action': action, 'results': results, 'ok': all(r['ok'] for r in results)}
