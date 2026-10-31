"""Idempotent domain objects for a coherent corporate lab."""
import json
import os
import subprocess

company = json.load(open('/opt/company.json'))
password = os.environ['BAIT_PASSWORD']
users = subprocess.check_output(['samba-tool', 'user', 'list'], text=True).splitlines()
groups = subprocess.check_output(['samba-tool', 'group', 'list'], text=True).splitlines()
for group in company['groups']:
    if group not in groups:
        subprocess.run(['samba-tool', 'group', 'add', group], check=True)
for employee in company['employees']:
    if employee['username'] not in users:
        subprocess.run(['samba-tool', 'user', 'create', employee['username'], password, '--description=' + employee['department'] + ' - SweetBerry lab'], check=True)
    group = employee['department'].replace(' ', '-')
    members = subprocess.check_output(['samba-tool', 'group', 'listmembers', group], text=True).splitlines()
    if employee['username'].casefold() not in {member.casefold() for member in members}:
        subprocess.run(['samba-tool', 'group', 'addmembers', group, employee['username']], check=True)
for computer in company['computers']:
    if subprocess.run(['samba-tool', 'computer', 'show', computer], capture_output=True).returncode:
        subprocess.run(['samba-tool', 'computer', 'create', computer], check=True)
print('Corporate lab objects ready')
