"""Store a provider key remotely without shell arguments or command logging."""
import getpass
import paramiko

client = paramiko.SSHClient()
client.load_system_host_keys()
client.set_missing_host_key_policy(paramiko.RejectPolicy())
password = getpass.getpass('SSH password: ')
client.connect('172.27.66.1', username='suredials', password=password, timeout=10)
key = getpass.getpass('Primalabs API key: ')
if not key or '\n' in key or '\r' in key:
    raise ValueError('Invalid key')
sftp = client.open_sftp()
path = '/home/suredials/sweetberry/.env'
with sftp.open(path) as stream:
    lines = stream.read().decode().splitlines()
updates = {'PRIMALABS_API_KEY': key, 'LLM_PROVIDER': 'primalabs', 'LLM_MODE': 'live',
           'LLM_MODEL': 'primalabs-ai/DeepSeek-V4.1-Flash-1017'}
lines = [line for line in lines if line.split('=', 1)[0] not in updates]
lines += [name + '=' + value for name, value in updates.items()]
with sftp.open(path, 'w') as stream:
    stream.write('\n'.join(lines) + '\n')
sftp.chmod(path, 0o600)
print('Provider configured; secret omitted.')
client.close()
