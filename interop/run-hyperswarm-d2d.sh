#!/usr/bin/env bash
# Phase-6: two D hyperswarm nodes meet on a topic. A JS bootstrapper is started;
# one D hyperswarm node joins the topic in server mode (announce + listen + accept),
# the other in client mode (lookup + connect); they discover each other, connect,
# and echo an encrypted message. The whole hyperswarm loop, D↔D.
set -u
cd "$(dirname "$0")/.."
echo "── building ──"
dub build -q --config=hyperswarm-d2d --compiler=ldc2 || { echo "FAIL build"; exit 1; }
(cd interop/hyperdht-js-peer && npm install --no-audit --no-fund >/dev/null 2>&1) || { echo "FAIL npm"; exit 1; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
ready="$work/boot"; port=$(( (RANDOM%4000)+49000 ))
echo; echo "── D hyperswarm server ⇄ D hyperswarm client (topic, via bootstrapper $port) ──"
node interop/hyperdht-js-peer/node.js "$port" "$ready" >"$work/js.log" 2>&1 & jspid=$!
for i in $(seq 1 100); do [ -s "$ready" ] && break; sleep 0.1; done
bp=$(cat "$ready" 2>/dev/null)
timeout 50 ./bin/hyperswarm-d2d "$bp" >"$work/d.log" 2>&1
dstatus=$?
kill "$jspid" 2>/dev/null; wait "$jspid" 2>/dev/null
echo "  D:  $(grep -vE 'leaking|EventCore|FD |Use .-debug|SO_RCVBUF|rto:' "$work/d.log" | grep -E 'OK|FAIL' | tail -2 | tr '\n' ' ')"
echo
if [ $dstatus -eq 0 ] && grep -q 'D<->D hyperswarm' "$work/d.log"; then
  echo "PASS  the full hyperswarm loop works D↔D (join server + client, discover, connect, echo)"; exit 0
else echo "FAIL  D↔D hyperswarm (exit=$dstatus)"; exit 1; fi
