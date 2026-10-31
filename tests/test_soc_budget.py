import copy
import json
from types import SimpleNamespace
from app.models import Event
from app.state import Engine
from app.soc_n2 import SocAnalyst, material_signature, material_features


def test_routine_updates_and_repeats_do_not_change_material_facts():
    session={'source_ip':'192.0.2.40','events':[{'action':'portscan','target_host':'dc01','mitre':'T1046','timestamp':1,'sequence':1}]}
    signature=material_signature(session,[])
    repeated=copy.deepcopy(session)
    repeated['events'].append({**session['events'][0],'timestamp':50,'sequence':2})
    context=[{'action':'flow','id':'new-id','timestamp':999,'destination':'192.0.2.9'}]
    assert material_signature(repeated,context)==signature
    repeated['events'].append({'action':'ldap_users','target_host':'dc01','mitre':'T1087.002'})
    assert material_signature(repeated,context)!=signature
    assert material_features(session,[]) <= material_features(repeated,context)
    assert material_signature({'events':[{'action':'web_visit','risk':0}]},context)==''


def test_provider_budget_persists_and_blocks_extra_calls(tmp_path,monkeypatch):
    monkeypatch.setenv('LLM_MODE','live')
    monkeypatch.setenv('SOC_MAX_CALLS_PER_CAPTURE','1')
    engine=Engine()
    engine.ingest(Event(timestamp=1,session_id='test',source_ip='192.0.2.40',sensor='wire',action='portscan'))
    analyst=SocAnalyst(tmp_path,engine,SimpleNamespace(snapshot=lambda:{'limitations':''}),live=True)
    analyst.read_context=lambda source:[]
    calls=[]
    analyst.analyze=lambda bundle:(calls.append(bundle) or analyst.fallback(bundle),'live')
    class Stop:
        count=0
        def is_set(self):return self.count>=2
        def wait(self,seconds):
            self.count+=1
            if self.count==1:engine.ingest(Event(timestamp=2,session_id='test',source_ip='192.0.2.40',sensor='wire',action='ldap_users'))
    analyst.stop=Stop()
    analyst.run()
    assert len(calls)==1
    assert analyst.status['state']=='budget_exhausted'
    assert analyst.status['provider_calls']==1
    saved=json.loads(analyst.budget_file.read_text())
    assert saved['calls']==1 and saved['source_features']
    restored=SocAnalyst(tmp_path,engine,analyst.observer,live=True)
    assert restored.provider_calls==1
    assert restored.source_features==analyst.source_features
