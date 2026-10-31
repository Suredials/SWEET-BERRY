"""Interactive deployment transport. Password stays only in process memory."""
import getpass
import json
import pathlib
import shlex
import sys
import paramiko

client = paramiko.SSHClient()
client.load_system_host_keys()
client.set_missing_host_key_policy(paramiko.RejectPolicy())
password = getpass.getpass('SSH password: ')
client.connect('172.27.66.1', username='suredials', password=password, timeout=10)
client.get_transport().set_keepalive(20)
sftp = client.open_sftp()
print('CONNECTED', flush=True)
for line in sys.stdin:
    try:
        req = json.loads(line)
        if 'upload' in req:
            root = pathlib.Path(req['upload'])
            dest = '/home/suredials/sweetberry'
            for file in root.rglob('*'):
                rel = file.relative_to(root)
                if any(p in {'.git', 'vendor', '.venv', '__pycache__', '.pytest_cache', '.env', 'runtime'} for p in rel.parts):
                    continue
                if file.is_file():
                    remote = dest + '/' + rel.as_posix()
                    parent = str(pathlib.PurePosixPath(remote).parent)
                    _, out, err = client.exec_command('mkdir -p ' + shlex.quote(parent))
                    out.channel.recv_exit_status()
                    sftp.put(str(file), remote)
            print('UPLOADED', flush=True)
        if 'cmd' in req:
            command = req['cmd']
            if req.get('sudo'):
                command = "sudo -S -p '' sh -c " + shlex.quote(command)
            incoming, out, err = client.exec_command(command, timeout=600)
            if req.get('sudo'):
                incoming.write(password + '\n')
                incoming.flush()
            print(out.read().decode(errors='replace'), flush=True)
            print(err.read().decode(errors='replace'), flush=True)
            print('EXIT', out.channel.recv_exit_status(), flush=True)
    except Exception as exc:
        print(type(exc).__name__, str(exc), flush=True)
