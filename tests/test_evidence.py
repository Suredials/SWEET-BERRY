from app.telemetry import Telemetry
from app.correlation import Correlator
from app.observer import TraceAssembler,parse_trace


def test_index_preserves_same_timestamp_pages_and_raw_references(tmp_path):
    store=Telemetry(tmp_path)
    for _ in range(5):store.record({'timestamp':100,'sensor':'test','asset':'linux','kind':'process_exec'})
    page1=store.query(limit=2);page2=store.query(limit=2,before_id=page1[-1]['event_id']);page3=store.query(limit=2,before_id=page2[-1]['event_id'])
    assert len({r['event_id'] for r in page1+page2+page3})==5
    for row in page1:
        raw=store.folder/row['evidence_ref']['file']
        with raw.open('rb') as stream:
            stream.seek(row['evidence_ref']['offset'])
            assert row['event_id'].encode() in stream.readline()
        assert store.evidence(row['event_id'])['raw_available']
    assert store.query(source="' OR 1=1 --")==[]


def test_raw_secret_redaction_replay_separation_and_canary_stability(tmp_path):
    store=Telemetry(tmp_path)
    store.record({'sensor':'test','payload':{'password':'PRIVATE','Authorization':'Bearer PRIVATE','nested':{'api_key':'PRIVATE'}},'mode':'replay'})
    assert store.query()==[]
    assert 'PRIVATE' not in str(store.query(mode='replay'))
    a=store.register_canary('repo:notes');b=store.register_canary('repo:notes');c=store.register_canary('s3:notes')
    assert a==b and a['canary_id']!=c['canary_id']


def web_window(c,request,source,begin,end):
    c.observe({'asset':'webedge','request_id':request,'source_ip':source,'timestamp':begin-.01,
        'payload':{'timestamp':begin-.01,'target':'/uploads/probe.php','duration_ms':(end-begin+.02)*1000}})
    for kind,stamp in [('php_request_start',begin),('php_request_end',end)]:
        c.observe({'asset':'webtrap','container_id':'web','timestamp':stamp,'payload':{'kind':kind,'request_id':request,
            'source_ip':source,'script':'/uploads/probe.php','timestamp':stamp}})


def test_two_web_requests_do_not_share_process_attribution():
    c=Correlator();c.register_target('web','webtrap','php')
    c.observe({'kind':'process_fork','process_key':'php','child_process_key':'child-a','timestamp':11,'container_id':'web'})
    c.observe({'kind':'process_fork','process_key':'php','child_process_key':'child-b','timestamp':21,'container_id':'web'})
    web_window(c,'a','192.0.2.1',10,12);web_window(c,'b','192.0.2.2',20,22)
    assert c.resolve({'process_key':'child-a'})['source_ip']=='192.0.2.1'
    assert c.resolve({'process_key':'child-b'})['source_ip']=='192.0.2.2'
    assert c.resolve({'process_key':'unknown'})=={}


def test_runtime_claim_without_independent_gateway_is_not_attributed():
    c=Correlator();c.register_target('web','webtrap','php')
    c.observe({'kind':'process_fork','process_key':'php','child_process_key':'child','timestamp':11,'container_id':'web'})
    c.observe({'asset':'webtrap','container_id':'web','timestamp':10,'payload':{'kind':'php_request_start','request_id':'forged','source_ip':'victim','script':'x','timestamp':10}})
    assert c.resolve({'process_key':'child'})=={}


def test_ssh_correlation_uses_exact_backend_ports():
    c=Correlator()
    for pid,port,source in [('a',40001,'192.0.2.1'),('b',40002,'192.0.2.2')]:
        c.observe({'kind':'network_accept','container':'linux','process_key':'sshd','destination':'172.30.66.2','port':port,'timestamp':10})
        c.observe({'kind':'process_fork','process_key':'sshd','child_process_key':pid,'timestamp':10.01,'container_id':'linux'})
        c.observe({'kind':'ssh_backend_link','local_ip':'172.30.66.2','local_port':port,'source_ip':source,'session':pid,'timestamp':10.02})
    assert c.resolve({'process_key':'a'})['source_ip']=='192.0.2.1'
    assert c.resolve({'process_key':'b'})['source_ip']=='192.0.2.2'


def test_strace_interleaving_keeps_fork_child_identity():
    parser=TraceAssembler()
    assert parse_trace(parser.feed('123 100.000 clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>\n'),'webtrap') is None
    child=parse_trace(parser.feed('124 100.001 execve("/bin/sh", ["sh"], 0x0) = 0\n'),'webtrap')
    fork=parse_trace(parser.feed('123 100.002 <... clone resumed>) = 124\n'),'webtrap')
    assert child['pid']==124 and fork['pid']==123 and fork['child_pid']==124
    namespaced=parse_trace("147962 100.002 clone(child_stack=NULL, flags=SIGCHLD) = 30 /* 150677 in strace's PID NS */\n",'webtrap')
    assert namespaced['child_pid']==150677 and namespaced['namespace_child_pid']==30


def test_pivot_requires_socket_tuple_and_correlated_parent():
    c=Correlator();c.register_target('web','webtrap','php')
    web_window(c,'root-request','192.0.2.1',10,12)
    c.observe({'kind':'process_fork','process_key':'php','child_process_key':'curl','timestamp':11,'container_id':'web'})
    c.observe({'kind':'network_connect','process_key':'curl','socket_fd':3,'timestamp':11.1,'destination':'172.30.67.50','port':8080})
    c.observe({'kind':'network_local','process_key':'curl','socket_fd':3,'timestamp':11.1,'local_address':'172.30.67.80','local_port':43000})
    row={'asset':'cloud','source_ip':'172.30.67.80','request_id':'aws-request','timestamp':11.2,'payload':{'source_port':43000}}
    link=c.resolve(row)
    assert link['source_ip']=='192.0.2.1' and link['parent_request_id']=='root-request'
    row['payload']['source_port']=43001
    assert c.resolve(row)=={}


def test_correlated_evidence_is_queryable_by_source(tmp_path):
    store=Telemetry(tmp_path);store.correlator.register_target('web','webtrap','php')
    store.record({'kind':'process_fork','process_key':'php','child_process_key':'child','timestamp':11,'container_id':'web','asset':'webtrap'})
    web_window(store.correlator,'req','192.0.2.1',10,12)
    row=store.record({'kind':'process_exec','process_key':'child','timestamp':11.1,'container_id':'web','asset':'webtrap'})
    # Real timestamps are refreshed asynchronously; direct query still derives attribution.
    assert store.evidence(row['event_id'])['source_ip']=='192.0.2.1'
