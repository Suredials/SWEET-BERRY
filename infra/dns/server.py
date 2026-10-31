"""Local-only DNS sink: records questions and never forwards to the Internet."""
import json
import socketserver
import struct
import threading
import time

HOSTS={'dc01.corp.local':'172.30.67.10','git01.corp.local':'172.30.67.42','git01':'172.30.67.42',
       'cloud01.corp.local':'172.30.67.50','cloud01':'172.30.67.50','backup01.corp.local':'172.30.66.20',
       'assistant01.corp.local':'172.30.67.70','support01.corp.local':'172.30.67.80'}
def answer(data,source):
    if len(data)<12 or len(data)>4096:return b''
    try:
        labels=[];position=12
        for _ in range(128):
            length=data[position];position+=1
            if length==0:break
            if length>63 or position+length>len(data):return b''
            labels.append(data[position:position+length].decode('ascii',errors='replace'));position+=length
        else:return b''
        qtype,qclass=struct.unpack('!HH',data[position:position+4]);end=position+4
        name='.'.join(labels).lower()
        ip=HOSTS.get(name)
        exists=ip is not None
        flags=0x8180 if exists else 0x8183
        record=b''
        if exists and qtype==1 and qclass==1:record=b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+bytes(map(int,ip.split('.')))
        response=data[:2]+struct.pack('!HHHHH',flags,1,1 if record else 0,0,0)+data[12:end]+record
        print(json.dumps({'timestamp':time.time(),'kind':'dns','source_ip':source,'sensor':'dns-sink',
            'dns':{'rrname':name,'type':qtype},'resolution':'local' if exists else 'blocked-nxdomain','destination':ip,
            'assessment':'domain observed; no external resolution or C2 attribution'}),flush=True)
        return response
    except (IndexError,ValueError,struct.error):return b''

class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data,socket=self.request;response=answer(data,self.client_address[0])
        if response:socket.sendto(response,self.client_address)
class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        header=self.request.recv(2)
        if len(header)!=2:return
        length=struct.unpack('!H',header)[0]
        if length>4096:return
        data=b''
        while len(data)<length:
            chunk=self.request.recv(length-len(data))
            if not chunk:return
            data+=chunk
        response=answer(data,self.client_address[0])
        if response:self.request.sendall(struct.pack('!H',len(response))+response)
class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
threading.Thread(target=Server(('0.0.0.0',53),TCP).serve_forever,daemon=True).start()
socketserver.UDPServer(('0.0.0.0',53),UDP).serve_forever()
