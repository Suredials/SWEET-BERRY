import datetime as dt
import json
import os
from pathlib import Path
import networkx as nx
import requests
import streamlit as st
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / '.env')
BASE = os.getenv('SWEETBERRY_API_URL', 'http://127.0.0.1:8000')
HEADERS = {'X-Admin-Token': os.getenv('ADMIN_TOKEN', '')}
st.set_page_config(page_title='SweetBerry', page_icon='🍓', layout='wide')
st.title('🍓 SweetBerry')
st.caption('Adaptive deception appliance · CORP.LOCAL · LLM proposes. Code decides.')


def call(method, path, **kwargs):
    response = requests.request(method, BASE + path, headers=HEADERS, timeout=4, **kwargs)
    response.raise_for_status()
    return response.json()


left, right = st.columns([3, 1])
with left:
    if st.button('RUN ATTACK REPLAY', type='primary'):
        try:
            call('POST', '/replay', json={'paced': True})
            st.toast('Offline replay started; live targets are unchanged.')
        except requests.RequestException as exc:
            st.error('Replay could not start: ' + str(exc))
with right:
    if st.button('Reset replay'):
        try:
            call('POST', '/reset-replay')
        except requests.RequestException as exc:
            st.error(str(exc))


@st.fragment(run_every='1s')
def panels():
    try:
        health = call('GET', '/health')
        document = call('GET', '/state')
    except (requests.RequestException, ValueError):
        st.error('Backend unavailable. Check sweetberry-api or run the offline CLI replay.')
        return
    status = health.get('sensors', {})
    st.caption(f"Collector: {health['status']} · Capture: {status.get('capture', status.get('mode', 'off'))} · Logs: {status.get('logs', 'offline')} · Reasoner: {health['llm_mode'].upper()}")
    if health.get('worker_error'):
        st.error('Collector error: ' + health['worker_error'])
    progress = document['replay']
    if progress['running']:
        st.progress(progress['step'] / max(1, progress['total']), text=f"Replay {progress['step']}/{progress['total']}")
    if progress.get('error'):
        st.error('Replay error: ' + progress['error'])
    sessions = document['sessions']
    if not sessions:
        st.info('Waiting for activity. Connect to SSH on port 2222 or start the offline replay.')
        return
    options = list(sessions)
    selected = st.selectbox('Active session', options, index=len(options) - 1, key='selected_session')
    session = sessions[selected]
    st.badge(session['mode'].upper(), color='orange' if session['mode'] == 'replay' else 'green')
    st.caption(f"Source: {session['source_ip']} · Targets: DC01 / backup01")
    events = session['events']
    duration = max(0, events[-1]['timestamp'] - events[0]['timestamp']) if events else 0
    cols = st.columns(5)
    cols[0].metric('Threat risk', f"{session['risk']} / 100")
    cols[1].metric('Deception level', f"{session['deception_level']} / 4")
    cols[2].metric('MITRE techniques', len(session['techniques']))
    cols[3].metric('Canary access attempts', sum(e['action'] == 'secret_access' for e in events))
    cols[4].metric('Observed duration', f'{duration:.1f}s')

    profile, intent = st.columns(2)
    with profile:
        st.subheader('Attacker profile')
        result = session['profile']
        st.write(result['likely_type'].replace('_', ' ').title())
        st.caption('Timing heuristic; does not establish whether an AI agent is present.')
        if result['confidence']:
            st.write(f"Heuristic confidence: {result['confidence']:.0%}")
    with intent:
        st.subheader('Intent assessment')
        result = session.get('reasoner', {})
        st.write(result.get('attacker_intent', 'unknown').replace('_', ' ').title())
        st.caption(f"{result.get('mode', 'mock').upper()} · confidence {result.get('confidence', 0):.0%}")
        st.write(result.get('reason', ''))
        if result.get('fallback_reason'):
            st.caption(result['fallback_reason'])

    st.subheader('Attack path')
    graph = nx.DiGraph()
    previous = None
    for event in events:
        technique = event.get('mitre')
        if technique:
            graph.add_node(technique, label=technique + '\n' + event['name'])
            if previous and previous != technique:
                graph.add_edge(previous, technique)
            previous = technique
    if graph:
        dot = ['digraph attack { rankdir=LR; node [shape=box,style=rounded];']
        dot += [f'{json.dumps(node)} [label={json.dumps(data["label"])}];' for node, data in graph.nodes(data=True)]
        dot += [f'{json.dumps(a)} -> {json.dumps(b)};' for a, b in graph.edges]
        dot.append('}')
        try:
            st.graphviz_chart('\n'.join(dot), width='stretch')
        except Exception:
            st.write(' → '.join(graph.nodes))
    else:
        st.caption('No mapped techniques yet.')

    timeline, actions = st.columns([3, 2])
    with timeline:
        st.subheader('Timeline')
        zone = dt.timezone(dt.timedelta(hours=-4))
        st.dataframe([{'Time (Bolivia)': dt.datetime.fromtimestamp(e['timestamp'], zone).strftime('%H:%M:%S'),
                       'Event': e['name'], 'Target': e['target_host'], 'MITRE': e.get('mitre') or '',
                       'Risk': e['risk'], 'Firewall': 'BLOCKED' if e['firewall']['blocked'] else ''}
                      for e in events[-40:]], hide_index=True, width='stretch')
    with actions:
        st.subheader('Environment mutations')
        mutations = session['mutations'] if session['mode'] == 'replay' else document['environment']['mutations']
        for mutation in mutations[-12:]:
            label = mutation['action'].replace('_', ' ')
            if mutation.get('ok'):
                st.success(('REPLAY · ' if mutation.get('simulated') else 'APPLIED · ') + label)
            else:
                st.error('FAILED · ' + label)
                for item in mutation.get('results', []):
                    if not item['ok']:
                        st.caption(item['host'] + ': ' + item['detail'])
        blocked = sum(e['firewall']['blocked'] for e in events)
        if blocked:
            st.warning(f'LLM FIREWALL · {blocked} input(s) quarantined. Deception engine continues operating.')


panels()
