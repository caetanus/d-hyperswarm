#!/usr/bin/env bash
#
# Phase-2 acceptance: a reliable UDX stream, D↔JS, against the REAL udx-native.
#
# The D dialer drives the vendored libudx through our vibe facade; the JS peer is
# holepunch's own udx-native. They exchange ports via files (no fixed ports),
# connect a stream each and echo a message. If the D side prints OK, our UDX is
# wire-compatible with the reference — the whole facade (UDP, timers, prepare/check,
# the C++-namespaced amalgamation) is proven against the real thing.
set -u
cd "$(dirname "$0")/.."

echo "── building ──"
dub build -q --config=udx-interop-peer --compiler=ldc2 \
    || { echo "FAIL  could not build the D udx peer"; exit 1; }
(cd interop/udx-js-peer && npm install --no-audit --no-fund >/dev/null 2>&1) \
    || { echo "FAIL  could not install udx-native"; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
jsport="$work/js_port"
dport="$work/d_port"

echo
echo "── D (vendored libudx over vibe) ⇄ JS (udx-native) ──"

# JS echo peer: id 1, dials the D peer (id 2)
node interop/udx-js-peer/echo.js 1 2 "$jsport" "$dport" >"$work/js.log" 2>&1 &
jspid=$!

# D dialer: id 2, dials the JS peer (id 1)
timeout 40 ./bin/udx-interop-peer 2 1 "$dport" "$jsport" >"$work/d.log" 2>&1
dstatus=$?

kill "$jspid" 2>/dev/null
wait "$jspid" 2>/dev/null

echo "  D:  $(tail -4 "$work/d.log" | tr '\n' ' ')"
echo "  JS: $(tail -4 "$work/js.log" | tr '\n' ' ')"
echo

if [ $dstatus -eq 0 ] && grep -q '^OK' "$work/d.log"; then
    echo "PASS  UDX is wire-compatible with udx-native (D⇄JS reliable stream)"
    exit 0
else
    echo "FAIL  D⇄JS UDX interop did not round-trip (exit=$dstatus)"
    exit 1
fi
