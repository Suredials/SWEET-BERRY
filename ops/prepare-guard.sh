#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
docker volume create sweetberry_guard-cache >/dev/null
if docker run --rm --network none -e HF_HUB_OFFLINE=1 -v sweetberry_guard-cache:/home/guard/.cache sweetberry-guard python -c 'from llm_guard.input_scanners import PromptInjection; PromptInjection(threshold=0.65)' >/tmp/sweetberry-guard-preflight.log 2>&1; then
  echo 'LLM Guard model cache verified offline'
else
  echo 'Preparing public LLM Guard model; no AWS or model-provider token required'
  timeout 900 docker run --rm --network host -v sweetberry_guard-cache:/home/guard/.cache sweetberry-guard python -c 'from llm_guard.input_scanners import PromptInjection; PromptInjection(threshold=0.65)' >>/tmp/sweetberry-guard-preflight.log 2>&1 || echo 'Guard classifier unavailable; chatbot will fail closed and show degraded protection'
fi
