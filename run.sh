#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
python3 -m pip install -q -r requirements.txt
echo "Shop: http://127.0.0.1:5001/   SOC: http://127.0.0.1:5001/soc"
python3 run.py
