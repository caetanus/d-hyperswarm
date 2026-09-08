#!/usr/bin/env bash
# Phase-5: the FULL connect-by-key against a REAL hyperdht server. A hyperdht node
# listens on a keyPair; the D client finds it via FIND_PEER, runs the Noise IK peer
# handshake over PEER_HANDSHAKE, opens a UDX stream to the server and runs the
# connection secret-stream from the handshake keys — then echoes an encrypted
# message. Proves the whole connect path is wire-compatible with hyperdht.
set -u
cd "$(dirname "$0")/.."
echo "── building ──"
dub build -q --config=dht-connect-peer --compiler=ldc2 || { echo "FAIL build"; exit 1; }
(cd interop/hyperdht-js-peer && npm install --no-audit --no-fund >/dev/null 2>&1) || { echo "FAIL npm"; exit 1; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
ready="$work/ready"; port=$(( (RANDOM%4000)+47000 ))
echo; echo "── D connect(pubKey) handshake ⇄ real hyperdht server (port $port) ──"
node interop/hyperdht-js-peer/server.js "$port" "$ready" >"$work/js.log" 2>&1 & jspid=$!
sleep 2
timeout 40 ./bin/dht-connect-peer "$port" "$ready" >"$work/d.log" 2>&1
dstatus=$?
kill "$jspid" 2>/dev/null; wait "$jspid" 2>/dev/null
echo "  D:  $(grep -vE 'leaking|EventCore|FD ' "$work/d.log" | tail -2 | tr '\n' ' ')"
echo "  JS: $(tail -1 "$work/js.log")"
echo
if [ $dstatus -eq 0 ] && grep -q '^OK' "$work/d.log"; then
  echo "PASS  full connect-by-key (encrypted stream) is wire-compatible with hyperdht"; exit 0
else echo "FAIL  connect handshake interop (exit=$dstatus)"; exit 1; fi
