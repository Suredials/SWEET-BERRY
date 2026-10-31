"""Read-only functional service checks. No exploitation or AS-REP probe."""
import argparse
import dns.resolver
from ldap3 import Connection, Server
import smbclient


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='172.27.66.10')
    host = parser.parse_args().host
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers, resolver.port = [host], 53
    print('DNS:', [str(row) for row in resolver.resolve('_ldap._tcp.dc._msdcs.corp.local', 'SRV')])
    connection = Connection(Server(host), user='analyst@CORP.LOCAL', password='SWEETBERRY_CANARY_DECOY_LabOnly!', auto_bind=True, auto_referrals=False)
    connection.search('DC=CORP,DC=LOCAL', '(objectClass=user)', attributes=['sAMAccountName'])
    print('LDAP users:', [str(entry.sAMAccountName) for entry in connection.entries])
    connection.search('DC=CORP,DC=LOCAL', '(objectClass=group)', attributes=['cn'])
    print('LDAP groups:', [str(entry.cn) for entry in connection.entries if str(entry.cn) in {'Engineering', 'Finance', 'IT-Operations', 'Backup-Operators'}])
    connection.search('DC=CORP,DC=LOCAL', '(objectClass=computer)', attributes=['cn'])
    print('LDAP computers:', [str(entry.cn) for entry in connection.entries])
    connection.unbind()
    smbclient.register_session(host, username='CORP\\analyst', password='SWEETBERRY_CANARY_DECOY_LabOnly!', connection_timeout=5)
    public = '\\\\' + host + '\\Public'
    print('SMB Public:', smbclient.listdir(public))
    with smbclient.open_file(public + '\\operations.txt', mode='r') as stream:
        print(stream.read())
    smbclient.reset_connection_cache()


if __name__ == '__main__':
    main()
