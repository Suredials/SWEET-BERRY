"""Minimal provider contract diagnostic, without logging credentials or telemetry."""
import json
from pathlib import Path
import os
from dotenv import load_dotenv
import requests

load_dotenv(Path(__file__).resolve().parents[1] / '.env')
response = requests.post('https://api.primalabs.ai/v1/chat/completions',
    headers={'Authorization':'Bearer ' + os.environ['PRIMALABS_API_KEY']},
    json={'model':os.environ['LLM_MODEL'], 'messages':[{'role':'user','content':'Return only this JSON object: {"status":"ok"}'}],
          'temperature':0, 'max_tokens':256, 'stream':False, 'response_format':{'type':'json_object'}},timeout=45)
print('HTTP',response.status_code,'TYPE',response.headers.get('content-type'))
try:
    data=response.json()
    print('KEYS',list(data))
    for choice in data.get('choices',[]):
        message=choice.get('message',{})
        print('CHOICE',choice.get('finish_reason'),'MESSAGE KEYS',list(message))
        print('CONTENT',repr(str(message.get('content',''))[:200]))
except ValueError:
    print('NON_JSON_PREFIX',repr(response.text[:200]))
