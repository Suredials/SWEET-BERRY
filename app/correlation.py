"""Correlation requires gateway/session identifiers, never just a shared IP."""
import threading


class Correlator:
    def __init__(self):
        self.lock=threading.RLock()
        self.targets={};self.parents={};self.forks={};self.windows={}
        self.pending_accept={};self.ssh_processes={};self.ssh_links={}
        self.connections={};self.origins={}

    def register_target(self,cid,role,init_key):
        with self.lock:self.targets[cid]={'role':role,'init_key':init_key}

    def observe(self,row):
        with self.lock:
            body=row.get('payload',{})
            if not isinstance(body,dict):body={}
            if row.get('kind')=='observer_attached':
                self.targets[row['container_id']]={'role':row['asset'],'init_key':row['init_process_key']}
            if row.get('asset')=='webedge' and row.get('request_id'):
                window=self.windows.setdefault(row['request_id'],{})
                window.update(source_ip=row['source_ip'],gateway_start=body.get('timestamp',row['timestamp']),
                    gateway_path=body.get('target'),gateway_confirmed=True)
                if body.get('duration_ms') is not None:window['gateway_end']=body.get('timestamp',row['timestamp'])+body['duration_ms']/1000
            if row.get('asset')=='webtrap' and body.get('kind') in {'php_request_start','php_request_end'} and body.get('request_id'):
                window=self.windows.setdefault(body['request_id'],{})
                window.update(runtime_source=body.get('source_ip'),runtime_path=body.get('script'),container_id=row.get('container_id'))
                window['runtime_start' if body['kind']=='php_request_start' else 'runtime_end']=body['timestamp']
            if row.get('kind')=='ssh_backend_link':
                self.ssh_links[(row.get('local_ip'),int(row.get('local_port') or 0))]={'source_ip':row['source_ip'],'ssh_session':row.get('session'),'timestamp':row['timestamp']}
            if row.get('kind')=='network_accept' and row.get('container')=='linux':
                self.pending_accept[row.get('process_key')]={'peer':(row.get('destination'),row.get('port')),'timestamp':row['timestamp']}
            if row.get('kind')=='network_connect' and row.get('socket_fd') is not None:
                self.connections[(row.get('process_key'),row['socket_fd'])]=row
            if row.get('kind')=='network_local' and row.get('socket_fd') is not None:
                connection=self.connections.get((row.get('process_key'),row['socket_fd']))
                if connection:self.origins[(row.get('local_address'),row.get('local_port'))]=connection
            if row.get('kind')=='process_fork' and row.get('child_process_key'):
                child=row['child_process_key'];parent=row['process_key']
                self.parents[child]=parent
                self.forks[child]={'parent':parent,'timestamp':row['timestamp'],'container_id':row.get('container_id')}
                accepted=self.pending_accept.pop(parent,None)
                if accepted and 0<=row['timestamp']-accepted['timestamp']<3:self.ssh_processes[child]=accepted
            if len(self.windows)>2000:
                for key in list(self.windows)[:500]:del self.windows[key]
            if len(self.forks)>10000:
                for key in list(self.forks)[:2000]:self.forks.pop(key,None);self.parents.pop(key,None);self.ssh_processes.pop(key,None)
            if len(self.origins)>5000:
                for key in list(self.origins)[:2000]:self.origins.pop(key,None)
            if len(self.connections)>5000:
                for key in list(self.connections)[:2000]:self.connections.pop(key,None)

    def resolve(self,row):
        key=row.get('process_key')
        if not key:
            body=row.get('payload',{})
            if not isinstance(body,dict):return {}
            with self.lock:
                origin=self.origins.get((row.get('source_ip'),body.get('source_port')))
                if not origin or abs(row['timestamp']-origin['timestamp'])>10:return {}
                expected={'forge':{'172.30.67.42','172.27.66.40'},'cloud':{'172.30.67.50','172.27.66.50'}}
                if origin.get('destination') not in expected.get(row.get('asset'),set()):return {}
                link=self.resolve(origin)
                if link:
                    return {**link,'request_id':row.get('request_id'),'parent_request_id':link.get('request_id'),
                            'parent_process_key':origin['process_key'],'correlation':'process_socket_gateway','correlation_confidence':.95}
            return {}
        with self.lock:
            current=key
            for _ in range(32):
                if current in self.ssh_processes:
                    accepted=self.ssh_processes[current];link=self.ssh_links.get(accepted['peer'])
                    if link and abs(link['timestamp']-accepted['timestamp'])<10 and not str(link['source_ip']).startswith('127.'):
                        return {'source_ip':link['source_ip'],'ssh_session':link['ssh_session'],'correlation':'cowrie_backend_tuple_process','correlation_confidence':1.0}
                fork=self.forks.get(current)
                if fork:
                    target=self.targets.get(fork['container_id'],{})
                    if fork['parent']==target.get('init_key') and target.get('role')=='webtrap':
                        resolved=self.window_at(fork['container_id'],fork['timestamp'])
                        if resolved:return resolved
                if current not in self.parents:break
                current=self.parents[current]
            target=self.targets.get(row.get('container_id'),{})
            if key==target.get('init_key') and target.get('role')=='webtrap':return self.window_at(row['container_id'],row['timestamp'])
        return {}

    def window_at(self,cid,stamp):
        for request_id,window in reversed(list(self.windows.items())):
            if window.get('container_id')!=cid or not window.get('gateway_confirmed'):continue
            if window.get('runtime_source')!=window.get('source_ip') or window.get('runtime_path')!=window.get('gateway_path'):continue
            begin=window.get('runtime_start');end=window.get('runtime_end')
            if begin is None or end is None or not begin<=stamp<=end:continue
            if not window['gateway_start']-.1<=begin<=window.get('gateway_end',end)+.1:continue
            return {'source_ip':window['source_ip'],'request_id':request_id,'correlation':'gateway_runtime_process','correlation_confidence':.95}
        return {}
