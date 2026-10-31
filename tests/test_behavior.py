from app.behavior import profile_events
from app.soc_n2 import SocAnalyst,validate_report

def make_events(times,statuses=None):
    return [{'timestamp':stamp,'target_host':('dc01','git01','cloud01')[i%3],
        'action':('ldap_users','repo_read','cloud_buckets')[i%3],'target':'/resource-'+str(i),
        'metadata':{'request_id':str(i),'status':(statuses or {}).get(i,200)}} for i,stamp in enumerate(times)]

def test_speed_is_automation_evidence_not_proof_of_agent():
    result=profile_events(make_events([0,.5,1,1.5,2,2.5,3]))
    assert result['likely_type']=='automation_like'
    assert result['confidence']<=.7
    assert 'not a calibrated probability' in result['note']

def test_recovery_can_be_agent_compatible_but_remains_uncertain():
    result=profile_events(make_events([0,.2,.8,1,1.5,2.2,2.4,3],{1:404,4:403}))
    assert result['likely_type']=='agent_compatible'
    assert result['features']['error_recovery_transitions']==2
    assert result['confidence']<=.65

def test_irregular_manual_pacing_and_insufficient_data():
    assert profile_events(make_events([0,3,25,29,50,56,80]))['likely_type']=='human_like'
    assert profile_events(make_events([0,.1,.2]))['likely_type']=='insufficient_evidence'

def test_one_request_and_static_resources_do_not_inflate_independence():
    events=make_events(list(range(10)))
    for row in events:row['metadata']['request_id']='one-request'
    assert profile_events(events)['likely_type']=='insufficient_evidence'
    for row in events:row['target']='/assets/main.js'
    assert profile_events(events)['features']['meaningful_events']==0

def test_model_cannot_turn_sparse_evidence_into_certain_ai_attribution():
    bundle={'events':[{'id':'known'}],'behavior_profile':{'features':{'independent_interactions':1}}}
    report=SocAnalyst.fallback(bundle)
    report['operator_assessment']={'style':'agent_compatible','confidence':.99,'rationale':'fast','evidence_ids':['known']}
    result=validate_report(report,bundle)
    assert result['operator_assessment']['style']=='insufficient_evidence'
    assert result['operator_assessment']['confidence']==0
