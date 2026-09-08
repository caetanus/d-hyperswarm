#!/usr/bin/env bash
#
# Phase-4 acceptance: our dht-rpc packet wire against a REAL dht-rpc node.
#
# A Node dht-rpc bootstrapper (holepunch's own) listens and auto-answers FIND_NODE;
# the D peer sends a FIND_NODE over plain vibe UDP and decodes the reply. A
# well-formed RESPONSE with our tid + the node's id proves the wire is compatible.
set -u
cd "$(dirname "$0")/.."

echo "── building ──"
dub build -q --config=dht-interop-peer --compiler=ldc2 \
    || { echo "FAIL  could not build the D dht peer"; exit 1; }
(cd interop/dht-js-peer && npm install --no-audit --no-fund >/dev/null 2>&1) \
    || { echo "FAIL  could not install dht-rpc"; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
ready="$work/ready"
port=$(( (RANDOM % 5000) + 45000 ))

echo
echo "── D (our dht-rpc wire) ⇄ JS (dht-rpc) over UDP, port $port ──"

node interop/dht-js-peer/node.js "$port" "$ready" >"$work/js.log" 2>&1 &
jspid=$!

timeout 30 ./bin/dht-interop-peer "$port" "$ready" >"$work/d.log" 2>&1
dstatus=$?

kill "$jspid" 2>/dev/null
wait "$jspid" 2>/dev/null

echo "  D:  $(tail -2 "$work/d.log" | tr '\n' ' ')"
echo "  JS: $(tail -2 "$work/js.log" | tr '\n' ' ')"
echo

if [ $dstatus -eq 0 ] && grep -q '^OK' "$work/d.log"; then
    echo "PASS  dht-rpc wire is compatible with dht-rpc"
    exit 0
else
    echo "FAIL  D⇄JS dht-rpc interop did not round-trip (exit=$dstatus)"
    exit 1
fi
