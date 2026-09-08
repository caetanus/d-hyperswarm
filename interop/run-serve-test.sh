#!/usr/bin/env bash
# Phase-6 server side: a direct D↔D connect. A D Server accepts an incoming peer
# handshake (Noise IK responder), accepts the client's UDX stream via a firewall
# callback, and runs the connection secret-stream; a D client connects straight to
# its address (no DHT discovery / relay) and echoes an encrypted message.
#
# This exercises the D server mechanics end to end. The wire primitives it reuses
# (IK handshake, secret-stream, UDX) are each already validated against the real JS
# on the client side; a JS-client → D-server interop needs DHT discoverability of
# the D server (the next step).
set -u
cd "$(dirname "$0")/.."
echo "── building ──"
dub build -q --config=dht-serve-peer --compiler=ldc2 || { echo "FAIL build"; exit 1; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
echo; echo "── D server ⇄ D client (direct, encrypted echo) ──"
timeout 30 ./bin/dht-serve-peer >"$work/d.log" 2>&1
dstatus=$?
echo "  $(grep -vE 'leaking|EventCore|FD |Use .-debug|SO_RCVBUF|rto:' "$work/d.log" | grep -E 'OK|FAIL' | tr '\n' ' ')"
echo
if [ $dstatus -eq 0 ] && grep -q 'D<->D encrypted echo' "$work/d.log"; then
  echo "PASS  the D server side accepts a connection and echoes (IK responder + UDX accept + secret-stream)"; exit 0
else echo "FAIL  D server side (exit=$dstatus)"; exit 1; fi
