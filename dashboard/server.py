"""SOC frontend. Backend credentials stay server-side."""
import os
from pathlib import Path
import time
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import requests
from urllib.parse import urlencode, quote
from app.models import ReplayRequest

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / '.env')
BASE = os.getenv('SWEETBERRY_API_URL', 'http://127.0.0.1:8000')
STATIC = Path(__file__).parent / 'static'
app = FastAPI(title='SweetBerry SOC', docs_url=None, redoc_url=None)
app.mount('/static', StaticFiles(directory=STATIC), name='static')


def proxy(method, path, body=None):
    try:
        response = requests.request(method, BASE + path, headers={'X-Admin-Token': os.getenv('ADMIN_TOKEN', '')}, json=body, timeout=6)
    except requests.RequestException as exc:
        raise HTTPException(503, 'Collector temporarily unavailable') from exc
    if not response.ok:
        raise HTTPException(response.status_code, 'Collector rejected this operation')
    return response.json()


@app.middleware('http')
async def security_headers(request: Request, call_next):
    if request.method == 'POST':
        origin = request.headers.get('origin')
        if origin and origin != str(request.base_url).rstrip('/'):
            return JSONResponse({'detail': 'Same-origin operation required'}, status_code=403)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    response.headers['Cache-Control'] = 'no-store' if request.url.path.startswith('/api/') else 'no-cache'
    return response


@app.get('/')
def index():
    return FileResponse(STATIC / 'index.html')


@app.get('/health')
def health():
    return {'status': 'ok', 'frontend': 'soc', 'version': '0.4.0'}


@app.get('/api/data')
def data():
    snapshot = proxy('GET', '/state')
    snapshot['health'] = proxy('GET', '/health')
    snapshot['server_time'] = time.time()
    # Keep the UI payload bounded while preserving raw JSONL evidence on disk.
    for session in snapshot['sessions'].values():
        session['event_count'] = session.get('sequence', len(session['events']))
        session['events'] = session['events'][-300:]
    return snapshot


@app.get('/api/transcripts')
def transcripts():
    return proxy('GET', '/transcripts')


@app.post('/api/replay')
def replay(body: ReplayRequest):
    return proxy('POST', '/replay', body.model_dump())


@app.post('/api/reset-replay')
def reset_replay():
    return proxy('POST', '/reset-replay')


@app.post('/api/soc/analyze')
def analyze_soc():
    return proxy('POST', '/soc/analyze')


@app.get('/api/telemetry')
def telemetry(request: Request):
    allowed={'source','asset','kind','process_key','request_id','canary_id','limit','before','before_id','important'}
    values={k:v for k,v in request.query_params.items() if k in allowed}
    return proxy('GET','/telemetry?'+urlencode(values))


@app.get('/api/evidence/{event_id}')
def evidence(event_id:str):
    if len(event_id)>200 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:._-' for c in event_id):raise HTTPException(400,'Invalid evidence identifier')
    return proxy('GET','/telemetry/'+quote(event_id,safe=''))


@app.get('/api/incidents')
def incidents():return proxy('GET','/incidents')
