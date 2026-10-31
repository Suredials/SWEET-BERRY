"""Reasoning boundary; no attacker strings or executable model output."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

ALLOWED_DECEPTIONS = {'do_nothing', 'expose_users', 'expose_backup_share', 'expose_cloud_credential'}


class Assessment(BaseModel):
    model_config = ConfigDict(extra='forbid')
    attacker_intent: Literal['credential_access', 'enumeration', 'domain_discovery', 'devops_recon', 'cloud_collection', 'system_discovery', 'unknown']
    confidence: float = Field(ge=0, le=1)
    next_deception: Literal['do_nothing', 'expose_users', 'expose_backup_share', 'expose_cloud_credential']
    reason: str = Field(max_length=500)


def sanitized_summary(events: list[dict], level: int) -> dict:
    from .mitre import RULES
    return {'recent_events': [e['action'] for e in events[-12:] if e['action'] in RULES and not e.get('firewall', {}).get('blocked')],
            'current_state': {'deception_level': level}}


def mock_reason(events: list[dict], level: int) -> dict:
    summary = sanitized_summary(events, level)
    focused = any(action in {'asrep_request', 'secret_access', 'cloud_inventory_read', 'password_spray_pattern'} for action in summary['recent_events'])
    actions = set(summary['recent_events'])
    intent, confidence, reason = 'enumeration', 0.65, 'Repeated discovery observations across the selected environment.'
    if focused:
        intent, confidence, reason = 'credential_access', 0.92, 'Credential-related requests or canary file interactions were observed.'
    elif actions & {'cloud_buckets', 'cloud_objects', 'cloud_object_read'}:
        intent, confidence, reason = 'cloud_collection', 0.82, 'The operator moved into bucket discovery and object access.'
    elif actions & {'repo_discovery', 'repo_read'}:
        intent, confidence, reason = 'devops_recon', 0.8, 'Repository browsing suggests interest in engineering and deployment context.'
    elif actions & {'ldap_users', 'ldap_groups', 'ldap_computers'}:
        intent, confidence, reason = 'domain_discovery', 0.78, 'Directory queries cover identities, groups or domain computers.'
    elif actions & {'system_discovery', 'process_discovery', 'network_discovery'}:
        intent, confidence, reason = 'system_discovery', 0.75, 'Shell commands are gathering host, process or network context.'
    result = Assessment.model_validate({'attacker_intent': intent,
            'confidence': confidence,
            'next_deception': 'do_nothing',
            'reason': reason}).model_dump()
    result['mode'] = 'mock'
    result['note'] = 'Deterministic session assessment; independent SOC N2 reports are published separately'
    return result
