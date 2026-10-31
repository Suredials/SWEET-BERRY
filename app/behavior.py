"""Operator-style estimates, explicitly distinct from identifying an AI operator."""
import re
import statistics

NOTE='Heuristic support for an interaction style, not a calibrated probability or proof of AI control. Humans using tools and scripts can look agentic; user agents are self-reported.'


def profile_events(events):
    meaningful=[];seen=set();distinct_requests=set()
    for event in events[-300:]:
        metadata=event.get('metadata',{})
        if metadata.get('maintenance') or event.get('firewall',{}).get('blocked'):continue
        target=str(event.get('target',''))
        if '/assets/' in target or re.search(r'\.(?:js|css|png|jpg|svg|ico|woff2?)(?:\?|$)',target):continue
        request=metadata.get('request_id') or event.get('request_id')
        if not isinstance(request,str) or len(request)>128:request=None
        key=(request,event.get('action'),event.get('target_host')) if request else (event.get('timestamp'),event.get('action'),target)
        if key in seen:continue
        seen.add(key);meaningful.append(event)
        distinct_requests.add(request or (event['timestamp'],event.get('action')))
    meaningful.sort(key=lambda e:e['timestamp'])
    times=[e['timestamp'] for e in meaningful]
    delays=[b-a for a,b in zip(times,times[1:]) if b-a>.03]
    median=statistics.median(delays) if delays else 0
    mean=statistics.mean(delays) if delays else 0
    variation=statistics.pstdev(delays)/mean if len(delays)>1 and mean else 0
    hosts={e.get('target_host') for e in meaningful}
    actions={e.get('action') for e in meaningful}
    recoveries=0
    for a,b in zip(meaningful,meaningful[1:]):
        status=a.get('metadata',{}).get('status',0)
        if isinstance(status,int) and status>=400 and 0<b['timestamp']-a['timestamp']<=10 and a.get('target')!=b.get('target'):recoveries+=1
    families={e.get('metadata',{}).get('client_family') for e in meaningful}
    agent_marker='self_reported_agent' in families
    features={'meaningful_events':len(meaningful),'independent_interactions':len(distinct_requests),
        'unique_services':len(hosts),'unique_actions':len(actions),'median_delay_seconds':round(median,3),
        'timing_variation':round(variation,3),'error_recovery_transitions':recoveries,
        'long_pauses':sum(d>10 for d in delays),'self_reported_agent_marker':agent_marker}
    label,confidence,signals='insufficient_evidence',0.0,[]
    if len(distinct_requests)>=6:
        fast=len(delays)>=4 and median<1
        regular=len(delays)>=5 and variation<.35
        broad=len(hosts)>=3 and times[-1]-times[0]<30
        score=2*fast+2*regular+broad+('cli_or_sdk' in families)
        if fast:signals.append('Rapid sequence across multiple meaningful interactions')
        if regular:signals.append('Repeated, regular timing consistent with scripted execution')
        if broad:signals.append('Multiple services contacted in a short observation window')
        if recoveries:signals.append(str(recoveries)+' changes of target after failed requests')
        if agent_marker:signals.append('Self-reported agent identifier; unverified and spoofable')
        if recoveries>=2 and len(hosts)>=2 and score>=2:
            label,confidence='agent_compatible',.60
            signals.append('Adaptive recovery plus automation-like behavior; scripts can also reproduce it')
        elif score>=2:label,confidence='automation_like',min(.70,.50+.04*score)
        elif median>2 and features['long_pauses']>=2 and variation>.5:
            label,confidence='human_like',.55
            signals.append('Irregular pacing and longer pauses compatible with manual interaction')
    if not signals:signals=['More independent interactions are needed to distinguish interaction styles']
    return {'likely_type':label,'confidence':round(confidence,2),'signals':signals,'features':features,'note':NOTE}
