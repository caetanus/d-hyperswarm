# d-hyperswarm phone↔desktop punch — status at pause (2026-09-20)

PAUSED by caetano ("reavaliar/pausar"). d-hyperswarm is a proactive Claude-built D
port of the Holepunch stack (NOT a caetano request); this note is factual state for
if/when it's reopened. No punch-relay work until caetano explicitly says so.

## Works, verified over the PUBLIC hyperdht network (fresh builds, this date)
- DHT: findNode/lookup converge; announce+lookup round-trip (dht-lookup-peer, dht-announce-peer).
- Hyperswarm client join: discovery over public works (topic announce + lookup find the record).
- App sync protocol E2E (over our own bootstrap, teammate's rig): auth → needsPairing →
  daemon.pair(code) → devices.confirm → push probe/have → 64K chunk frames each acked →
  complete → file lands sha-verified; RESUME across a server restart (spool survives).
- Same-key reconnect: FIXED (connection.d onCloseInternal; swarm.d evicts registry via it,
  not the app-overwritable onClose). Confirmed green.

## MISSING / FAILED — the punch round (the only blocker)
First live acceptance of the relayed CONNECT over real NAT FAILED. Trace (VPS netns
MASQUERADE client → home CGNAT server, public bootstrap):
- cmd=0 PEER_HANDSHAKE → relay 162.251.160.77:34065: forwarded to the server (server sees
  201-byte first=0x03 recvs) and answered (client gets 120/122-byte reply). GOOD.
- cmd=1 PEER_HOLEPUNCH → SAME relay, SAME target=BLAKE2b(pubkey), SAME null token: the
  public relay neither answers nor forwards it (client: silence; server: never receives a
  cmd=1). So d-hyperswarm's punch-round RELAY protocol is not wire-compatible with the
  PUBLIC hyperdht relay nodes. It worked only against a local/reference relay.
- Root, per stage-e-plan.md DEFERRED notes: "relays left empty — client reuses the handshake
  relay"; "token-echo / relay-tracking (isServerRelay=false)" deferred; analyze/reopen loop,
  TRY_LATER + random-punch gate deferred. The public nodes almost certainly require the punch
  round to echo the node-issued token from the handshake round-trip and/or route via the
  server-designated relay, not a null-token reuse of the handshake relay.
- Secondary: the client's NAT sample flaps OPEN/firewalled between retries (122 vs 120-byte
  handshake reply → server flips holepunch on/off). connectViaHolepunch samples each connect.
- openConnection (swarm.d) was wired this session to try connectViaHolepunch first (holepunch),
  OPEN direct-dial fallback — so the CLIENT now attempts the punch when firewalled. Server side
  (serve.d handlePeerHandshake) only holepunches on the CLIENT's firewall, never its own — so
  open-client→CGNAT-server never punches (not the phone's path; phone is the CGNAT client).

## To reopen: the decisive first diagnostic
Capture the REFERENCE JS hyperdht's PEER_HOLEPUNCH round to a public relay (two JS peers over
public, tcpdump the relay UDP) and byte-compare to our cmd=1 → shows the exact token/target/
relay field the public nodes require. Then implement hyperdht's punch-round relay fidelity.
This is real protocol work, uncertain size.

## Uncommitted this session (working tree)
- d-hyperswarm: connection.d onCloseInternal (+ swarm.d evictions), rpc.d PW_HS_TRACE diag,
  swarm.d openConnection→connectViaHolepunch, dub.json sourceFiles(udx_amalgam.o), vendor/
  build-libudx-android.sh + hs_udx_wrappers.c, build-dswarm-android.sh.
- photo-wagon: core/p2p/hswarm.d (HsTransport + PW_HS_BOOTSTRAP), node.d + p2pbridge.d udx seams.
Caetano commits only when he asks.

## 2026-09-21 — RESOLVED: the punch round is wire-compatible with the public hyperdht
Reopened on caetano's "vai até terminar" + "teste o nosso hyperdht contra o hyperdht node".
Root causes (read from hyperdht 6.34.0 lib/router.js + server.js + connect.js, then proven on the rig):
1. Client PEER_HOLEPUNCH `peerAddress` must be the SERVER's address (the relay node forwards there,
   stamping our address on the way). We sent OUR address, so the public node forwarded the round
   to ourselves. Fixed in connect.d: rounds go to the server's announced relay (holepunch.relays,
   preferring the handshake relay) with peerAddress = the server; sent from the punch socket.
2. Server must answer a relayed round as a FROM_SERVER *request* (mode 1, id 0, same tid) back to
   the relay, from its PUNCH socket (the node stamps that mapping as the client's target). We sent a
   plain REPLY. Fixed in serve.d.
3. Server must advertise holepunch.relays (nodes the announce landed on + our address as each saw
   us) — a JS client treats an empty list as CANNOT_HOLEPUNCH. node.d records announceRelays.
4. Token echo (isServerRelay) and verified addresses now as in hyperdht; TRY_LATER honoured.
5. Server opens its NAT mapping toward the client's punch socket on every round (low-TTL
   openSession) — otherwise the client's beacons poison a conntrack NAT before our first beacon.
6. Client treats "already connected" (server's fast-open ping landed) as success, not failure.
Acceptance, public hyperdht, home NAT <-> hetzner Docker NAT, interop/dht-pipe + pub-{server,client}.js:
  JS server <- D client: 4 MiB in 2.7 s, hold 30 s PASS
  D server <- JS client: 4 MiB in 3.0 s, hold 30 s PASS
  D server <- D client:  4 MiB in 2.5 s, hold 30 s PASS
ut: 19 modules pass. Still deferred: analyze/reopen loop for RANDOM NATs, random-punch rate limiter
(client waits on TRY_LATER but never issues it), relayThrough (blind-relay fallback).
