"""Create local configuration without printing deployment secrets."""
from pathlib import Path
import secrets

root = Path(__file__).resolve().parents[1]
env = root / '.env'
if not env.exists():
    env.write_text('LAB_IP=172.27.66.1\nDOMAIN_PASSWORD=' + secrets.token_hex(20) + 'Aa!7\nBAIT_PASSWORD=SWEETBERRY_CANARY_DECOY_LabOnly!\nADMIN_TOKEN=' + secrets.token_hex(24) + '\nLLM_PROVIDER=primalabs\nLLM_MODE=mock\n')
    env.chmod(0o600)
for name in ('dc', 'cowrie', 'collector', 'portal', 'forge', 'cloud', 'linux', 'canary'):
    (root / 'runtime' / name).mkdir(parents=True, exist_ok=True)
for name in ('log/cowrie', 'lib/cowrie/tty', 'lib/cowrie/downloads', 'run'):
    (root / 'runtime/cowrie' / name).mkdir(parents=True, exist_ok=True)
print('Configuration ready; secrets omitted.')

current = env.read_text(encoding='utf-8')
for name in ('CHAT_BROKER_TOKEN', 'GITEA_ADMIN_PASSWORD'):
    if not any(line.startswith(name+'=') for line in current.splitlines()):
        current += name+'='+secrets.token_hex(24)+'\n'
env.write_text(current,encoding='utf-8')
for name in ('webedge','chatbot','broker','telemetry','network','pcap'):
    (root/'runtime'/name).mkdir(parents=True,exist_ok=True)
