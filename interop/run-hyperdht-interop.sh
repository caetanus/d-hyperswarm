#!/usr/bin/env bash
# Phase-5 acceptance: announce/lookup against a REAL hyperdht node. A local hyperdht
# bootstrapper stores and serves; the D node announces a peer record under a shared
# topic (signed) and looks it up, finding itself. Deterministic (one node), so it
# proves the announce signature the node verifies + the lookup decode are
# wire-compatible with hyperdht.
set -u
cd "$(dirname "$0")/.."
echo "── building ──"
dub build -q --config=dht-announce-peer --compiler=ldc2 || { echo "FAIL build"; exit 1; }
(cd interop/hyperdht-js-peer && npm install --no-audit --no-fund >/dev/null 2>&1) || { echo "FAIL npm"; exit 1; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
ready="$work/ready"; port=$(( (RANDOM%4000)+46000 ))
echo; echo "── D announce/lookup ⇄ real hyperdht node (port $port) ──"
node interop/hyperdht-js-peer/node.js "$port" "$ready" >"$work/js.log" 2>&1 &
jspid=$!
timeout 40 ./bin/dht-announce-peer "$port" "$ready" >"$work/d.log" 2>&1
dstatus=$?
kill "$jspid" 2>/dev/null; wait "$jspid" 2>/dev/null
echo "  D:  $(grep -vE 'leaking|EventCore|FD ' "$work/d.log" | tail -3 | tr '\n' ' ')"
echo "  JS: $(tail -1 "$work/js.log")"
echo
if [ $dstatus -eq 0 ] && grep -q '^OK' "$work/d.log"; then
  echo "PASS  announce/lookup wire-compatible with hyperdht"; exit 0
else echo "FAIL  announce/lookup interop (exit=$dstatus)"; exit 1; fi
