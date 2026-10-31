"""Fast deterministic tests plus deployed API health and offline replay."""
import json
import sys
import time
from pathlib import Path
import requests
from dotenv import dotenv_values
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.replay import run_scenario
from app.state import Engine

root = Path(__file__).resolve().parents[1]
config = dotenv_values(root / '.env')
for attempt in range(10):
    try:
        response = requests.get('http://127.0.0.1:8000/health', timeout=2)
        break
    except requests.ConnectionError:
        if attempt == 9:
            raise
        time.sleep(0.5)
response.raise_for_status()
print('[PASS] API', response.json())
response = requests.get('http://127.0.0.1:8000/state', headers={'X-Admin-Token': config['ADMIN_TOKEN']}, timeout=5)
response.raise_for_status()
print('[PASS] authenticated state')
result = run_scenario(Engine())
assert result['risk'] == 100 and result['deception_level'] == 4
assert result['events'][-1]['firewall']['blocked']
print('[PASS] detector, firewall, replay')
print('SweetBerry smoke tests OK')
