"""Sensor health and a host-side storage watchdog for the vulnerable target."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
import requests


class Coverage:
    def __init__(self,root,telemetry,live=False):
        self.root,self.telemetry,self.live=root,telemetry,live
        self.stop=threading.Event();self.cached={};self.checked=0
        self.intervention=None
    def start(self):
        if self.live:threading.Thread(target=self.watch,daemon=True,name='containment-watchdog').start()
    def snapshot(self):
        if time.monotonic()-self.checked<10 and self.cached:return self.cached
        services={}
        if self.live:
            try:
                names=['sweetberry-network-sensor','sweetberry-pcap','sweetberry-chat-broker']
                states=subprocess.run(['systemctl','is-active',*names],capture_output=True,text=True,timeout=3).stdout.splitlines()
                services=dict(zip(names,states))
            except (OSError,subprocess.SubprocessError):services={'state':'unavailable'}
        stats=self.telemetry.query(asset='network',kind='stats',limit=1)
        packet_stats=stats[0].get('payload',{}).get('stats',{}) if stats else {}
        try:guard=requests.get('http://172.30.67.71:8000/health',timeout=1).json() if self.live else {'classifier':'offline'}
        except requests.RequestException:guard={'classifier':'unavailable','engine':'ProtectAI/llm-guard'}
        pcaps=list((self.root/'runtime/pcap').glob('lab.pcap*'))
        self.cached={'services':services,'guard':guard,'pcap_bytes':sum(p.stat().st_size for p in pcaps if p.is_file()),
                     'pcap_budget_bytes':1024*1024*1024,'disk_free_bytes':shutil.disk_usage(self.root).free,
                     'capture_stats':packet_stats.get('capture',{}),'last_network_stats':stats[0]['timestamp'] if stats else None,
                     'containment_intervention':self.intervention,
                     'limits':'Web target: 16 PIDs, 0.75 CPU, 128 MiB address space per process, 10 MiB per file, 64 MiB /tmp. Memory cgroup unavailable on this kernel.',
                     'storage_watchdog':'Stops webtrap when upload storage exceeds 128 MiB or 256 files.'}
        self.checked=time.monotonic()
        return self.cached
    def watch(self):
        while not self.stop.wait(2):
            try:
                result=subprocess.run(['docker','volume','inspect','sweetberry_webtrap-uploads','--format','{{.Mountpoint}}'],capture_output=True,text=True,timeout=3)
                directory=Path(result.stdout.strip())
                if str(directory)!='/var/lib/docker/volumes/sweetberry_webtrap-uploads/_data':continue
                total,count=0,0
                for current,dirs,files in os.walk(directory,followlinks=False):
                    dirs[:]=[name for name in dirs if not Path(current,name).is_symlink()]
                    for name in files:
                        try:total+=Path(current,name).lstat().st_size;count+=1
                        except FileNotFoundError:continue
                        if total>128*1024*1024 or count>256:break
                    if total>128*1024*1024 or count>256:break
                if total>128*1024*1024 or count>256:
                    subprocess.run(['docker','compose','stop','-t','2','webtrap'],cwd=self.root,capture_output=True,timeout=8)
                    self.intervention={'timestamp':time.time(),'reason':'upload_storage_limit','bytes':total,'files':count}
                    self.telemetry.record({'sensor':'host-watchdog','asset':'webtrap','kind':'containment_intervention','trust':'host-control',**self.intervention})
                    self.stop.wait(30)
            except (OSError,ValueError,subprocess.SubprocessError):pass
    def close(self):self.stop.set()
