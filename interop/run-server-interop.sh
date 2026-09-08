#!/usr/bin/env bash
# Phase-6 server interop: a REAL hyperdht client connects to a D SERVER by public
# key. A JS bootstrapper is started; the D server bootstraps off it, announces
# itself (listen), and echoes; a JS hyperdht client finds the D server by key and
# connects — the bootstrapper relays the PEER_HANDSHAKE to the D server, which
# responds (FROM_SERVER), accepts the client's UDX stream and runs the connection
# secret-stream. Proves the D server side is wire-compatible with a real client.
set -u
cd "$(dirname "$0")/.."
echo "── building ──"
dub build -q --config=dht-server-peer --compiler=ldc2 || { echo "FAIL build"; exit 1; }
(cd interop/dht-server-js && npm install --no-audit --no-fund >/dev/null 2>&1) || { echo "FAIL npm"; exit 1; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
bootReady="$work/boot"; serverKey="$work/serverkey"; port=$(( (RANDOM%4000)+49000 ))

echo; echo "── JS client ⇄ D server (discovered by key, relayed handshake) ──"
# JS bootstrapper + client; writes its bootstrap port, waits for the D server key.
node interop/dht-server-js/client.js "$port" "$bootReady" "$serverKey" >"$work/js.log" 2>&1 & jspid=$!
# wait for the bootstrapper to be up
for i in $(seq 1 100); do [ -s "$bootReady" ] && break; sleep 0.1; done
bp=$(cat "$bootReady" 2>/dev/null)
# D server bootstraps off it, announces, serves
timeout 40 ./bin/dht-server-peer "$bp" "$serverKey" >"$work/d.log" 2>&1 & dpid=$!
wait "$jspid"; jstatus=$?
kill "$dpid" 2>/dev/null; wait "$dpid" 2>/dev/null

echo "  D:  $(grep -vE 'leaking|EventCore|FD |Use .-debug|SO_RCVBUF|rto:' "$work/d.log" | tail -3 | tr '\n' ' ')"
echo "  JS: $(grep -E 'PASS|FAIL|open|connecting' "$work/js.log" | tail -2 | tr '\n' ' ')"
echo
if [ $jstatus -eq 0 ] && grep -q '^PASS' "$work/js.log"; then
  echo "PASS  a real hyperdht client connects to the D server by key and echoes"; exit 0
else echo "FAIL  server interop (js exit=$jstatus)"; exit 1; fi
