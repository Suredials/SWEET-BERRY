import asyncio
from contextlib import asynccontextmanager
import hmac
import os
from pathlib import Path
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from .models import Event, ReplayRequest
from .state import Engine
from .event_bus import EventBus
from .deception import apply_mutation
from .replay import scenario_events, CATALOG
from .sensors import Sensors
from .intel import Inventory, local_intelligence, transcripts
from .observer import Observer
from .soc_n2 import SocAnalyst
from .telemetry import Telemetry
from .evidence_reader import EvidenceReader
from .coverage import Coverage

ROOT = Path(__file__).resolve().parents[1]


def create_app(token: str | None = None, live: bool = False, engine=None):
    secret = token or os.getenv('ADMIN_TOKEN', '')
    state = engine or Engine(ROOT / 'runtime/collector/events.jsonl', actor=apply_mutation if live else None)
    bus = EventBus(state)
    sensors = Sensors(bus, ROOT, os.getenv('CAPTURE_INTERFACE', 'wlan0'), os.getenv('LAB_IP', '172.27.66.1')) if live else None
    replay = {'running': False, 'step': 0, 'total': 0, 'error': ''}
    task = None
    inventory = Inventory(live=live)
    telemetry = Telemetry(ROOT)
    def correlated_signal(row):
        body=row.get('payload',{})
        command=row['asset']=='webtrap' and row.get('kind')=='process_exec' and row.get('result')=='observed' and row.get('syscall_phase')=='complete'
        if row['asset'] not in {'forge','cloud'} and not command:return
        event=Event(timestamp=row['timestamp'],session_id='live:'+row['source_ip'],source_ip=row['source_ip'],sensor='correlator',
            target_host='support01' if command else 'git01' if row['asset']=='forge' else 'cloud01',action='web_command_execution' if command else body.get('action','http_contact'),
            target=str(row.get('executable','') if command else body.get('target',''))[:256],metadata={'evidence_id':row['event_id'],'request_id':row.get('request_id'),
            'correlation':row.get('correlation'),'evidence':'confirmed' if body.get('status',500)<400 else 'attempted'})
        if command:event.metadata['evidence']='confirmed'
        sensors.emit(event) if sensors else None
    telemetry.on_correlated=correlated_signal
    state.telemetry = telemetry
    reader = EvidenceReader(ROOT, telemetry, live=live)
    observer = Observer(ROOT, live=live, telemetry=telemetry)
    analyst = SocAnalyst(ROOT, state, observer, live=live)
    analyst.telemetry = telemetry
    coverage = Coverage(ROOT,telemetry,live=live)

    @asynccontextmanager
    async def lifespan(app):
        bus.thread.start()
        telemetry.start()
        if sensors:
            sensors.start()
        observer.start()
        reader.start()
        coverage.start()
        analyst.start()
        yield
        if task and not task.done():
            task.cancel()
        if sensors:
            sensors.close()
        observer.close()
        reader.close()
        coverage.close()
        telemetry.close()
        analyst.close()
        bus.stop.set()
        bus.thread.join(timeout=2)

    app = FastAPI(title='SweetBerry control plane', lifespan=lifespan)
    app.state.engine = state

    def authorized(x_admin_token: str = Header(default='')):
        if not secret:
            raise HTTPException(503, 'ADMIN_TOKEN must be configured')
        if not hmac.compare_digest(x_admin_token.encode(), secret.encode()):
            raise HTTPException(401, 'Invalid token')

    @app.middleware('http')
    async def limit_body(request: Request, call_next):
        from starlette.responses import JSONResponse
        if int(request.headers.get('content-length', '0') or 0) > 16384:
            return JSONResponse({'detail': 'Request too large'}, status_code=413)
        if len(await request.body()) > 16384:
            return JSONResponse({'detail': 'Request too large'}, status_code=413)
        return await call_next(request)

    @app.get('/health')
    def health():
        return {'status': 'ok', 'version': '0.4.0', 'live': live, 'llm_mode': analyst.status['mode'], 'queue_depth': bus.queue.qsize(),
                'worker_error': bus.error, 'sensors': sensors.status if sensors else {'mode': 'offline'}}

    @app.get('/state', dependencies=[Depends(authorized)])
    def get_state():
        sessions = state.snapshot()
        return {'sessions': sessions, 'environment': state.world, 'replay': dict(replay),
                'assets': inventory.snapshot(), 'intelligence': local_intelligence(sessions), 'scenarios': CATALOG,
                'observer': observer.snapshot(), 'soc_n2': analyst.snapshot(),
                'telemetry': telemetry.snapshot(), 'coverage': {**reader.status,**coverage.snapshot()}, 'intel_v2': telemetry.intelligence()}

    @app.get('/telemetry', dependencies=[Depends(authorized)])
    def query_telemetry(source: str = '', asset: str = '', kind: str = '', process_key: str = '', request_id: str = '', canary_id: str = '', limit: int = 100, before: float | None = None, before_id: str = '', important: bool = False):
        return telemetry.query(source=source,asset=asset,kind=kind,process_key=process_key,request_id=request_id,canary_id=canary_id,limit=limit,before=before,before_id=before_id,important=important)

    @app.get('/telemetry/{event_id}', dependencies=[Depends(authorized)])
    def get_evidence(event_id: str):
        row=telemetry.evidence(event_id)
        if not row:raise HTTPException(404,'Evidence not found')
        return row

    @app.get('/incidents', dependencies=[Depends(authorized)])
    def get_incidents():return telemetry.incidents()

    @app.get('/intel', dependencies=[Depends(authorized)])
    def get_intel():return telemetry.intelligence()

    @app.post('/soc/analyze', dependencies=[Depends(authorized)])
    def analyze_now():
        analyst.request()
        return {'queued': live, 'scope': 'live telemetry only'}

    @app.get('/transcripts', dependencies=[Depends(authorized)])
    def get_transcripts():
        return transcripts() if live else []

    @app.get('/events', dependencies=[Depends(authorized)])
    def get_events():
        return [event for s in state.snapshot().values() for event in s['events']]

    @app.post('/events', dependencies=[Depends(authorized)])
    def emit(event: Event):
        if live:
            raise HTTPException(403, 'Live events come only from sensors')
        return state.ingest(event)

    async def replay_task(events, paced, pace_seconds):
        try:
            state.clear_replays()
            for i, event in enumerate(events):
                state.ingest(event)
                replay['step'] = i + 1
                if paced:
                    await asyncio.sleep(pace_seconds)
        except Exception as exc:
            replay['error'] = type(exc).__name__
        finally:
            replay['running'] = False

    @app.post('/replay', dependencies=[Depends(authorized)])
    async def start_replay(body: ReplayRequest):
        nonlocal task
        if replay['running']:
            raise HTTPException(409, 'Replay already running')
        try:
            events = scenario_events(body.scenario)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        replay.update(running=True, step=0, total=len(events), error='', scenario=body.scenario)
        task = asyncio.create_task(replay_task(events, body.paced, body.pace_seconds))
        return dict(replay)

    @app.post('/reset-replay', dependencies=[Depends(authorized)])
    async def reset_replay():
        nonlocal task
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        state.clear_replays()
        replay.update(running=False, step=0, total=0, error='')
        return {'ok': True}

    return app


def from_environment():
    from dotenv import load_dotenv
    load_dotenv(ROOT / '.env')
    return create_app(live=os.getenv('SWEETBERRY_LIVE', 'false').lower() == 'true')
