import re
import unicodedata

PATTERNS = ('ignore previous instructions', 'system prompt', 'developer message', 'reveal your prompt', 'you are chatgpt', 'forget your instructions', 'act as', 'execute this command', 'reveal your hidden configuration')


def firewall(payload: str) -> dict:
    normalized = unicodedata.normalize('NFKC', payload[:8192]).casefold()
    normalized = ''.join(c for c in normalized if unicodedata.category(c) != 'Cf')
    normalized = re.sub(r'\s+', ' ', normalized)
    blocked = any(pattern in normalized for pattern in PATTERNS)
    return {'blocked': blocked, 'reason': 'prompt_injection_pattern' if blocked else 'no_pattern', 'risk': 80 if blocked else 0}
