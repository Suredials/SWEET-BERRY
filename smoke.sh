#!/bin/sh
set -eu
cd "$(dirname "$0")"
.venv/bin/python -m pytest -q
.venv/bin/python scripts/smoke.py
