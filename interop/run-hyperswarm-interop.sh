#!/usr/bin/env bash
# Phase-6: the hyperswarm layer against a REAL hyperswarm. A JS hyperswarm server
# joins a topic (announce + listen) behind a bootstrapper; the D hyperswarm client
# joins the same topic, discovers the server's public key by looking the topic up,
# and attempts to connect.
#
# Validated here: topic discovery (join -> lookup -> peer's public key) is
# wire-compatible with the real hyperswarm. Completing the encrypted connection
# through a relay node still needs the dht-rpc/udx socket unification (a real
# hyperswarm always reaches the server through a relay, which reports the client's
# rpc-socket source; our streams live on a separate socket) — the next step.
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
if [ $dstatus -eq 0 ] && grep -q '^OK discovered' "$work/d.log"; then
  if grep -q 'encrypted echo' "$work/d.log"; then
    echo "PASS  hyperswarm join + encrypted connection is wire-compatible"
  else
    echo "PASS  hyperswarm topic discovery is wire-compatible (encrypted connection pending socket unification)"
  fi
  exit 0
else echo "FAIL  hyperswarm interop (exit=$dstatus)"; exit 1; fi
