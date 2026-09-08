# d-hyperswarm — Holepunch hyperswarm in D

**Goal:** a D implementation of Holepunch's hyperswarm stack that is **wire-compatible
with the real Holepunch network** (Pear/Keet/the live hyperdht). This is a stack of its
own — it is *not* libp2p and shares no protocol with it. It reuses only the foundation
we already trust: vibe-core fibers, libsodium, and the methodology proven on
libp2p-dlang and d-webrtc-v3 (vendor rare C deps, byte-exact vectors and live interop
as the contract, design before code, adversarial review each advance).

## Why wire-compatibility, not a hyperswarm-like layer

The point is to join the real network, so every layer must match the reference JS
byte-for-byte. The reference implementations (consulted, never laundered) are pinned as
siblings under `~/lab`:

| Layer | Repo | Pin |
|---|---|---|
| compact-encoding | holepunchto/compact-encoding | `d579287` |
| UDX (C core) | holepunchto/libudx | `01d6630` (the commit udx-native fetches) |
| secret-stream | holepunchto/hyperswarm-secret-stream | (clone when phase 3) |
| dht-rpc | holepunchto/dht-rpc | (clone when phase 4) |
| hyperdht | holepunchto/hyperdht | (clone when phase 5) |
| hyperswarm | holepunchto/hyperswarm | (clone when phase 6) |

## The stack, bottom-up (with per-phase acceptance)

1. **compact-encoding** — the serialization codec the whole stack speaks. ~1.1k LOC,
   one file, pure. **PORT-PURE.** Acceptance: byte-exact vectors generated from the real
   JS (`tests/vectors/`), asserted by the D port.

2. **UDX** — `libudx` is a standalone C library (~5–6k LOC C: reliable, multiplexed,
   congestion-controlled streams over UDP; BBR/RACK/TLP/MTU). `udx-native` is only a
   binding. We **vendor the C** (`vendor/libudx`, pin `01d6630`) — we do not reimplement
   reliable UDP. The C API already exposes the holepunch primitives we will need:
   `udx_stream_change_remote`, `udx_stream_relay_to`, `udx_stream_firewall`.

   **libudx is written against libuv, but we do NOT use libuv.** Instead we compile its C
   against our own `uv.h` and implement the ~40-function libuv subset it uses on top of
   vibe-core — a **libuv→vibe facade**. One event loop (vibe's), single-threaded, no
   cross-thread. This is possible because libudx never calls `uv_run` (we drive the
   callbacks) and treats uv handles as opaque but for `.data`. Full spec:
   `notes/uv-facade.md`. Acceptance: reliable echo D↔JS over UDX.

3. **secret-stream** — `Noise_XX_Ed25519_ChaChaPoly_BLAKE2b`. DH runs **directly on the
   Ed25519 curve** (`crypto_scalarmult_ed25519_noclamp`), **no** ed25519→x25519
   conversion (unlike libp2p Noise). Empty prologue, 3-byte little-endian length prefix,
   post-handshake payloads via `crypto_secretstream_xchacha20poly1305`. ~700 LOC.
   **PORT-WITH-CRYPTO** (all in libsodium). Acceptance: encrypted echo D↔JS over UDX.

4. **dht-rpc** — Kademlia **over UDX** (not raw UDP). Node IDs are `BLAKE2b(ip+port)`,
   *not* the ed25519 identity. Commands PING/PING_NAT/FIND_NODE/DOWN_HINT/DELAYED_PING;
   messages in compact-encoding. ~2.3k LOC. **PORT-PURE + BLAKE2b.** Acceptance:
   `find_node`/`ping` against the live bootstrap nodes.

5. **hyperdht** — announce/lookup by topic, connect-by-ed25519-pubkey, and **the
   holepunch protocol** (the riskiest layer, ~6–8k LOC). Relay-coordinated (blind-relay,
   up to two hops), NAT sampling (≥4 DHT pings → OPEN/CONSISTENT/RANDOM), birthday-
   paradox strategy (~256 local sockets on the RANDOM side), round-synchronized punch
   with a 1-byte `HOLEPUNCH=[0]` beacon and a TTL schedule. The interop-fragile constants
   (`lib/holepuncher.js`, `lib/constants.js`, `lib/connect.js`, `lib/router.js`,
   `lib/nat.js`) must be read **verbatim** before hardcoding. **PORT-WITH-CRYPTO.**
   Acceptance: connect-by-key on a LAN (no NAT), then holepunch across real NATs.

6. **hyperswarm** — `join(topic, {server, client})` / `on('connection')`, connection
   dedup (deterministic by comparing Noise public keys), jittered backoff (≈1s/5s/15s/
   10min). ~1.3k LOC. **PORT-PURE.** Acceptance: `join` a topic and connect D↔JS.

## Crypto (all libsodium, already bound in the sibling projects)

- BLAKE2b generichash (DHT node IDs)
- ed25519 sign + `crypto_scalarmult_ed25519_noclamp` (Noise DH on the Edwards curve)
- `crypto_secretstream_xchacha20poly1305` (stream payloads)

## Live network

Bootstrap (from `hyperdht/lib/constants.js`), for testing against the real DHT:

```
node1.hyperdht.org:49737   (88.99.3.86)
node2.hyperdht.org:49737   (142.93.90.113)
node3.hyperdht.org:49737   (138.68.147.8)
```

Isolated local DHT for unit tests: bootstrap `[]`.

## Status

- [x] Phase 1: compact-encoding port + byte-exact vectors (16 tests, 0 failed)
- [ ] Phase 2: UDX via the libuv→vibe facade (decided facade over laundering, 2026-09-07)
  - [x] libudx vendored (`vendor/libudx`, pin 01d6630)
  - [x] header milestone: shim `uv.h` (`vendor/libudx-shim`), all 9 src/*.c compile against it
  - [x] uv symbol isolation: facade renamed to `hsuv_*` (no global `uv_*`)
  - [x] amalgamation: libudx built as ONE C++ TU in `namespace udx` — ALL symbols
        (internals + public API) enclosed under `udx::`, zero global `udx_*`/`uv_*`;
        C++↔D link proven (link test); D calls the API via extern(C++, "udx")
  - [x] loop + timer + buf: `Loop` runner on vibe (fire due timers → sleep to next
        deadline/wake → repeat); hsuv_timer_*/now/hrtime/buf_init/close/is_active live;
        tests: one-shot fires once after timeout, repeating re-arms until stopped
  - [x] UDP on vibe UDPConnection: init/bind/recv_start (reader fiber → alloc+recv
        cbs)/getsockname/send (fiber)/try_send (raw non-blocking sendmsg)/set_ttl
        (setsockopt via fd — holepunch needs it)/buffer-sizes/fileno; multicast stubbed.
        Test: a datagram sent through the facade is received on the vibe loop
  - [x] prepare/check (loop-phase hooks: prepare before poll, check after) + strerror
  - [x] **udx echo D↔D**: real libudx drives a reliable stream through the facade
        (D binding via the controlled hs_udx_* C-ABI surface); "hello" round-trips
        A→B→A. 21 tests, 0 failed, deterministic across runs
  - [ ] getaddrinfo + interfaces (for udx_lookup / interface-change events — deferred)
  - [x] **acceptance: interop vs the real JS UDX (udx-native)** — a reliable stream
        round-trips D⇄JS (interop/run-udx-interop.sh), deterministic. UDX is
        wire-compatible with the reference. **Phase 2 core complete.**
- [ ] Phase 3: secret-stream (Noise_XX_Ed25519_ChaChaPoly_BLAKE2b) — wire in notes/secret-stream-port.md
  - [x] crypto primitives: HMAC-BLAKE2b, HKDF, ChaCha20-Poly1305 IETF, Ed25519 DH —
        byte-exact vs the JS (noise-handshake/noise-curve-ed), on libsodium
  - [x] Noise XX handshake (SymmetricState + the 3 messages) — byte-exact vs the JS
        with fixed static+ephemeral keys; random-ephemeral run agrees on tx/rx/hash
  - [x] secret-stream transport (uint24-LE framing + secretstream Push/Pull) — sans-io
        SecretStream; D⇄D handshake + encrypted echo
  - [x] **acceptance: D⇄JS vs @hyperswarm/secret-stream** — handshake + encrypted echo
        round-trips over TCP (interop/run-secretstream-interop.sh), deterministic.
        secret-stream is wire-compatible. **Phase 3 complete.**
- [ ] Phase 4: dht-rpc (Kademlia over UDP/UDX) — wire in the module docs
  - [x] packet wire codec (request/reply/nodeId) byte-exact; FIND_NODE round-trips
        against a real dht-rpc node (interop/run-dht-interop.sh)
  - [x] Kademlia routing table + iterative query engine (find_node toward a target) —
        live lookup converges on the real network (interop/run-dht-lookup.sh)
  - [x] tokens + external commands (announce/lookup ride on the query engine)
- [x] Phase 5: hyperdht — announce/lookup by topic + connect-by-key (encrypted stream)
  - [x] announce/lookup a topic, wire-compat vs a real hyperdht (interop/run-hyperdht-interop.sh)
  - [x] Noise IK peer handshake (noise-wrap) + secret-stream from the IK keys
  - [x] **connect-by-key end to end**: DHT lookup → IK handshake over PEER_HANDSHAKE →
        UDX stream → connection secret-stream → encrypted echo, wire-compat vs a real
        hyperdht server (interop/run-connect-interop.sh). Key: advertise our real udx
        address in the handshake `peerAddress` so the server's OPEN-path connects to our
        facade socket (our rpc and udx live on separate sockets; hyperdht uses one).
  - [ ] HOLEPUNCH (holepuncher.js) for non-OPEN/NAT peers — deferred (OPEN/LAN works)
  - [ ] D server side (accept incoming connects) so two D peers connect
- [ ] Phase 6: hyperswarm — join(topic)/on(connection), dedup + backoff
  - [x] client layer: Hyperswarm (keyPair + Dht + udx socket), join(topic) discovery
        loop (lookup → connect by pubkey), Connection (UDX stream + secret-stream),
        de-dup by remote pubkey — hyperswarm.swarm / hyperswarm.connection
  - [x] **full client path wire-compat vs a real hyperswarm** — join → lookup discovers
        the server → connect through a relay → peer handshake → UDX stream →
        secret-stream → encrypted echo (interop/run-hyperswarm-interop.sh)
  - [x] dht-rpc unified onto the udx socket (rpc + streams share one socket like
        hyperdht, so a server/relay sees our handshake from our stream socket) — rpc.d
  - [x] server side: accept a connection — IK responder + UDX stream accept (firewall)
        + connection secret-stream, proven D↔D direct (hyperswarm.dht.serve, run-serve-test.sh)
  - [ ] make the D server discoverable via the DHT so a JS client connects to it
        (announce router entry + relay-forward of PEER_HANDSHAKE) + wire into join(server=true)
  - [ ] connection backoff/retry (RetryTimer), maxPeers/limit
  - [ ] holepunch (holepuncher.js) for non-OPEN/NAT peers (deferred; OPEN/LAN works)
