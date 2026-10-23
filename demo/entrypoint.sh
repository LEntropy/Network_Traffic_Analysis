#!/usr/bin/env bash
# Starts the three demo processes inside one container:
#   netaudit-agent  live capture on loopback, tcp port 8080 -> /tmp/events.jsonl
#   target_server   HTTP test server on 127.0.0.1:8080
#   ui_server       web UI and API on 0.0.0.0:8000
set -euo pipefail

: > /tmp/events.jsonl
netaudit-agent -i lo -f "tcp port 8080" -o /tmp/events.jsonl --idle-timeout 30 &
export AGENT_PID=$!

python3 /demo/target_server.py 8080 &
sleep 0.5

echo "netaudit demo: open http://localhost:8000"
exec python3 /demo/ui_server.py 8000
