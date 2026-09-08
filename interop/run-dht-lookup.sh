#!/usr/bin/env bash
# Phase-4 acceptance (live): our iterative Kademlia lookup against the REAL hyperdht
# network. The D node bootstraps off node{1,2,3}.hyperdht.org, sends FIND_NODE toward
# a random target and folds in the closerNodes each real node returns until it
# converges on the closest ~20. Proves the whole dht-rpc stack (wire + RPC + routing
# table + iterative query) interoperates with the live global DHT.
set -u
cd "$(dirname "$0")/.."
echo "── building ──"
dub build -q --config=dht-lookup-peer --compiler=ldc2 || { echo "FAIL build"; exit 1; }
echo
echo "── D node ⇄ live hyperdht (node{1,2,3}.hyperdht.org:49737) ──"
timeout 40 ./bin/dht-lookup-peer 2>/dev/null
status=$?
if [ $status -eq 0 ]; then
  echo "PASS  iterative lookup converged on the live hyperdht network"
else
  echo "SKIP/FAIL  live DHT unreachable or too few nodes (exit=$status) — needs outbound UDP"
fi
exit $status
