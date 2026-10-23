#!/usr/bin/env bash
# Runs inside the dev container (docker/dev.Dockerfile) with the source tree at /src.
# 1) sanitizer build  2) unit tests  3) end-to-end run on a real loopback capture.
# Results are written to /src/test-results for tools/make_report.py.
set -euo pipefail

OUT=/src/test-results
BUILD=/build
mkdir -p "$OUT"

step() { printf '\n\033[1;36m==== [%s] %s ====\033[0m\n' "$1" "$2"; }

step 1/3 "Build (Debug + AddressSanitizer + UBSan)"
cmake -S /src -B "$BUILD" -G Ninja -DCMAKE_BUILD_TYPE=Debug -DNETAUDIT_SANITIZE=ON >/dev/null
cmake --build "$BUILD"

step 2/3 "Unit tests (GoogleTest)"
"$BUILD/netaudit_tests" --gtest_color=yes --gtest_output="xml:$OUT/unit.xml"

step 3/3 "End-to-end: capture real HTTP traffic on loopback, then analyse it"
WWW=$(mktemp -d)
echo "hello" > "$WWW/index.html"
head -c 50000 /dev/urandom | base64 > "$WWW/big.txt"
(cd "$WWW" && exec python3 -m http.server 8080 >/dev/null 2>&1) &
SERVER=$!
tcpdump -i lo -U -w "$OUT/e2e.pcap" tcp port 8080 2>/dev/null &
DUMP=$!
sleep 1.5

echo "-> sending requests to 127.0.0.1:8080"
python3 - <<'EOF'
import http.client

def call(method, path, body=None, headers={}):
    c = http.client.HTTPConnection("127.0.0.1", 8080)
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    data = r.read()
    print(f"   {method:4} {path:<22} -> {r.status} ({len(data)} bytes)")
    c.close()

call("GET", "/index.html")
call("GET", "/big.txt")                      # ~67 KB response, many segments
call("GET", "/missing?id=42")                # 404
call("HEAD", "/index.html")                  # no body despite Content-Length
call("POST", "/upload", body=b"name=test&v=1",
     headers={"Content-Type": "application/x-www-form-urlencoded"})  # 501
EOF
sleep 1
kill "$DUMP" "$SERVER" 2>/dev/null || true
wait 2>/dev/null || true

echo "-> netaudit-agent -r e2e.pcap"
"$BUILD/netaudit-agent" -r "$OUT/e2e.pcap" -o "$OUT/e2e.jsonl" 2> "$OUT/e2e_stats.json"
python3 - "$OUT/e2e.jsonl" "$OUT/e2e_stats.json" <<'EOF'
import json, sys
print(f"   {'METHOD':6} {'URI':<22} {'STATUS':>6} {'RESP BYTES':>10}  FLAGS")
for line in open(sys.argv[1]):
    r = json.loads(line)
    print(f"   {r.get('method',''):6} {r.get('uri',''):<22} {r['status']:>6} "
          f"{r.get('resp_body_bytes',0):>10}  {r.get('flags','')}")
s = json.loads(open(sys.argv[2]).read())
print(f"   packets={s['packets']} flows={s['flows']} delivered_bytes={s['delivered_bytes']} "
      f"gaps={s['gap_events']} events={s['events']}")
EOF

printf '\n\033[1;32mAll steps finished. Results in test-results/\033[0m\n'
