"""The actual Protect AI LLM Guard package; unavailable scanners fail closed."""
import threading
import unicodedata
from fastapi import FastAPI
from pydantic import BaseModel, Field
from llm_guard.input_scanners import BanSubstrings, PromptInjection, Secrets
from llm_guard.input_scanners.ban_substrings import MatchType

app = FastAPI(docs_url=None, redoc_url=None)
rules = BanSubstrings(substrings=['ignore previous instructions', 'system prompt', 'developer message',
    'reveal your prompt', 'forget your instructions', 'execute this command', 'reveal your hidden configuration',
    'ignora las instrucciones', 'ignora instrucciones anteriores'], match_type=MatchType.STR, case_sensitive=False)
classifier = None
secrets_scanner = Secrets()
status = {'engine': 'ProtectAI/llm-guard', 'version': '0.3.16', 'rules': True, 'classifier': 'loading',
          'scanners':['BanSubstrings','Secrets','PromptInjection']}
lock = threading.Lock()


def load():
    global classifier
    try:
        import torch
        torch.set_num_threads(2)
        classifier = PromptInjection(threshold=0.65)
        status['classifier'] = 'ready'
    except Exception as exc:
        status['classifier'] = 'unavailable:' + type(exc).__name__


threading.Thread(target=load, daemon=True).start()


class Scan(BaseModel):
    text: str = Field(max_length=12000)
    direction: str = 'input'


@app.get('/health')
def health():
    return dict(status)


@app.post('/scan')
def scan(body: Scan):
    text = unicodedata.normalize('NFKC', body.text)
    text = ''.join(c for c in text if unicodedata.category(c) != 'Cf')
    with lock:
        _, valid, risk = rules.scan(text)
        if not valid:
            return {'valid': False, 'ready': True, 'risk': float(risk), 'scanner': 'LLMGuard.BanSubstrings'}
        _,valid,risk=secrets_scanner.scan(text)
        if not valid:return {'valid':False,'ready':True,'risk':float(risk),'scanner':'LLMGuard.Secrets'}
        if body.direction == 'output':
            secret = any(value in text for value in ('PRIMALABS_API_KEY', 'ADMIN_TOKEN', 'CHAT_BROKER_TOKEN'))
            return {'valid': not secret, 'ready': True, 'risk': float(secret), 'scanner': 'LLMGuard.BanSubstrings+Secrets+output-policy'}
        if classifier is None:
            return {'valid': False, 'ready': False, 'risk': 0, 'scanner': status['classifier']}
        _, valid, risk = classifier.scan(text)
        return {'valid': bool(valid), 'ready': True, 'risk': max(0.0,min(1.0,float(risk))), 'raw_score':float(risk),'scanner': 'LLMGuard.PromptInjection'}
