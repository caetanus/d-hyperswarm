#!/usr/bin/env bash
# Phase-6: the hyperswarm layer against a REAL hyperswarm. A JS hyperswarm server
# joins a topic (announce + listen) behind a bootstrapper; the D hyperswarm client
# joins the same topic, discovers the server's public key by looking the topic up,
# connects through a relay node and echoes an encrypted message.
#
# Proves the full hyperswarm client path is wire-compatible with the real
# hyperswarm: join -> lookup discovers the server -> connect through a relay node
# -> peer handshake -> UDX stream -> connection secret-stream -> encrypted echo.
# (dht-rpc and the connection streams share one udx socket, so the address the
# server sees our handshake from is the socket our stream lives on.)
set -u
cd "$(dirname "$0")/.."
echo "── building ──"
dub build -q --config=hyperswarm-peer --compiler=ldc2 || { echo "FAIL build"; exit 1; }
(cd interop/hyperswarm-js-peer && npm install --no-audit --no-fund >/dev/null 2>&1) || { echo "FAIL npm"; exit 1; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
ready="$work/ready"; port=$(( (RANDOM%4000)+49000 ))
echo; echo "── D hyperswarm client ⇄ real hyperswarm server (bootstrap $port) ──"
node interop/hyperswarm-js-peer/server.js "$port" "$ready" >"$work/js.log" 2>&1 & jspid=$!
sleep 4
timeout 45 ./bin/hyperswarm-peer "$ready" >"$work/d.log" 2>&1
dstatus=$?
kill "$jspid" 2>/dev/null; wait "$jspid" 2>/dev/null
echo "  D:  $(grep -vE 'leaking|EventCore|FD |Use .-debug|SO_RCVBUF' "$work/d.log" | tail -3 | tr '\n' ' ')"
echo "  JS: $(tail -1 "$work/js.log")"
echo
if [ $dstatus -eq 0 ] && grep -q "encrypted echo" "$work/d.log"; then
  echo "PASS  full hyperswarm (join -> discover -> connect -> encrypted echo) is wire-compatible"; exit 0
else echo "FAIL  hyperswarm interop (exit=$dstatus)"; exit 1; fi
