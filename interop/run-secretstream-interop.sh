#!/usr/bin/env bash
#
# Phase-3 acceptance: secret-stream, D⇄JS, against the REAL @hyperswarm/secret-stream.
#
# The D dialer runs our own Noise XX + secret-stream over a vibe TCP connection; the
# JS peer is holepunch's @hyperswarm/secret-stream over a plain TCP socket, echoing.
# They handshake and echo a message. If the D side prints OK, our secret-stream is
# wire-compatible with the reference — the crypto, the Noise transcript and the
# framing all match.
set -u
cd "$(dirname "$0")/.."

echo "── building ──"
dub build -q --config=secretstream-interop-peer --compiler=ldc2 \
    || { echo "FAIL  could not build the D secret-stream peer"; exit 1; }
(cd interop/secretstream-js-peer && npm install --no-audit --no-fund >/dev/null 2>&1) \
    || { echo "FAIL  could not install @hyperswarm/secret-stream"; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
port="$work/js_port"

echo
echo "── D (our secret-stream) ⇄ JS (@hyperswarm/secret-stream) over TCP ──"

node interop/secretstream-js-peer/echo.js "$port" >"$work/js.log" 2>&1 &
jspid=$!

timeout 40 ./bin/secretstream-interop-peer "$port" >"$work/d.log" 2>&1
dstatus=$?

kill "$jspid" 2>/dev/null
wait "$jspid" 2>/dev/null

echo "  D:  $(tail -3 "$work/d.log" | tr '\n' ' ')"
echo "  JS: $(tail -3 "$work/js.log" | tr '\n' ' ')"
echo

if [ $dstatus -eq 0 ] && grep -q '^OK' "$work/d.log"; then
    echo "PASS  secret-stream is wire-compatible with @hyperswarm/secret-stream"
    exit 0
else
    echo "FAIL  D⇄JS secret-stream interop did not round-trip (exit=$dstatus)"
    exit 1
fi
