"""Generate project-scoped Suricata and PCAP configuration."""
import json
from pathlib import Path
import subprocess
import yaml

root=Path(__file__).resolve().parents[1]
folder=root/'runtime/network';folder.mkdir(parents=True,exist_ok=True)
(root/'runtime/pcap').mkdir(parents=True,exist_ok=True)
aliases=' or '.join('host 172.27.66.'+str(n) for n in (10,20,30,40,50,60,70,80))
scope=f'(({aliases}) or net 172.30.67.0/24 or net 172.30.66.0/24) and not host 172.27.66.1 and not host 172.30.67.1 and not host 172.30.66.1 and not port 8001 and not host 172.30.67.71'
(folder/'capture.filter').write_text(scope)
interfaces=['wlan0']
for name in ('sweetberry_frontend','sweetberry_targets'):
    data=json.loads(subprocess.check_output(['docker','network','inspect',name]))[0]
    interfaces.append(data.get('Options',{}).get('com.docker.network.bridge.name') or 'br-'+data['Id'][:12])
config=yaml.safe_load(Path('/etc/suricata/suricata.yaml').read_text())
config['default-log-dir']=str(folder)
config['vars']['address-groups']['HOME_NET']='[172.27.66.0/24,172.30.67.0/24,172.30.66.0/24]'
config['af-packet']=[{'interface':name,'threads':1,'cluster-id':95+i,'cluster-type':'cluster_flow','defrag':True,'use-mmap':True,'tpacket-v3':True,'bpf-filter':scope} for i,name in enumerate(interfaces)]
config['outputs']=[{'eve-log':{'enabled':True,'filetype':'regular','filename':'eve.json',
    'types':['alert','anomaly','flow','dns','http','tls','ssh','smb',{'files':{'force-magic':True,'force-hash':['sha256']}},{'stats':{'totals':True,'threads':False}}]}}]
config['stats']={'enabled':True,'interval':10}
config['rule-files']=[str(folder/'sweetberry.rules')]
(folder/'sweetberry.rules').write_text('''alert tcp any any -> $HOME_NET any (msg:"SweetBerry TCP SYN burst - investigate"; flags:S; detection_filter:track by_src,count 15,seconds 10; sid:9900001; rev:1;)
alert http any any -> $HOME_NET any (msg:"SweetBerry upload endpoint interaction"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/upload"; sid:9900002; rev:1;)
''')
(folder/'suricata.yaml').write_text('%YAML 1.1\n---\n'+yaml.safe_dump(config,sort_keys=False))
print('Capture interfaces:',','.join(interfaces))
