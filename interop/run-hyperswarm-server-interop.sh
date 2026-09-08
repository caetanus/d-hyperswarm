#!/usr/bin/env bash
# Phase-6: a REAL hyperswarm CLIENT connects to a D hyperswarm SERVER on a topic.
# A JS bootstrapper is started; the D hyperswarm node joins the topic in server mode
# (announce + listen + accept + echo); a JS hyperswarm client joins the same topic,
# discovers the D server, connects, and expects an encrypted echo. Proves the D
# hyperswarm server side is wire-compatible with the real hyperswarm.
set -u
cd "$(dirname "$0")/.."
echo "── building ──"
dub build -q --config=hyperswarm-dserver --compiler=ldc2 || { echo "FAIL build"; exit 1; }
(cd interop/hyperswarm-js-peer && npm install --no-audit --no-fund >/dev/null 2>&1) || { echo "FAIL npm"; exit 1; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
bootReady="$work/boot"; serverKey="$work/serverkey"; port=$(( (RANDOM%4000)+49000 ))

echo; echo "── JS hyperswarm client ⇄ D hyperswarm server (topic) ──"
node interop/hyperswarm-js-peer/client.js "$port" "$bootReady" "$serverKey" >"$work/js.log" 2>&1 & jspid=$!
for i in $(seq 1 100); do [ -s "$bootReady" ] && break; sleep 0.1; done
bp=$(cat "$bootReady" 2>/dev/null)
timeout 45 ./bin/hyperswarm-dserver "$bp" "$serverKey" >"$work/d.log" 2>&1 & dpid=$!
wait "$jspid"; jstatus=$?
kill "$dpid" 2>/dev/null; wait "$dpid" 2>/dev/null

echo "  D:  $(grep -vE 'leaking|EventCore|FD |Use .-debug|SO_RCVBUF|rto:' "$work/d.log" | grep -E 'OK|FAIL|up' | tail -2 | tr '\n' ' ')"
echo "  JS: $(grep -E 'PASS|FAIL|connection' "$work/js.log" | tail -2 | tr '\n' ' ')"
echo
if [ $jstatus -eq 0 ] && grep -q '^PASS' "$work/js.log"; then
  echo "PASS  a real hyperswarm client connects to the D hyperswarm server on a topic"; exit 0
else echo "FAIL  hyperswarm server interop (js exit=$jstatus)"; exit 1; fi
