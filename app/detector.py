from .mitre import RULES

ALIASES = {'request_asrep': 'asrep_request', 'access_cloud_canary': 'secret_access', 'read_backup': 'file_discovery'}


def detect(action: str) -> dict:
    action = ALIASES.get(action, action)
    technique, name, category, risk, level = RULES.get(action, (None, action.replace('_', ' ').title(), 'observation', 0, 0))
    return dict(action=action, mitre=technique, name=name, category=category, risk=risk, level=level)
