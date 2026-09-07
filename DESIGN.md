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
  - [ ] loop + timer + buf (impl + test: a timer fires on the vibe loop)
  - [ ] UDP on vibe UDPConnection
  - [ ] prepare/check + close
  - [ ] getaddrinfo + interfaces + strerror
  - [ ] udx echo D↔D, then acceptance D↔JS
- [ ] Phase 3: secret-stream
- [ ] Phase 4: dht-rpc
- [ ] Phase 5: hyperdht (+ holepunch)
- [ ] Phase 6: hyperswarm
