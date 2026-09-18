# Holepunch Stage E — relay-coordinated PEER_HOLEPUNCH round (automatic sync)

Goal: wire the holepuncher (Stages A–D, validated live on the rig with manual
`--fire-at`) into connect.d/serve.d so the round-synchronised punch happens
AUTOMATICALLY during connect-by-key — retiring `--fire-at`. The round number the
two sides exchange over the relay gives the simultaneity that `--fire-at` faked
(both fire the same round together → neither is the nf_nat "second mover" that gets
its outbound external port reallocated — see the 2026-09-18 rig conclusion in
[[hyperswarm-interop-project]]).

Reference: hyperdht lib/connect.js (client, ~L209–770) + lib/server.js (server,
~L216–545). Constants verbatim from the same files.

## The relay decision (resolved — no new infra)
PEER_HOLEPUNCH (command 1) is routed to the server THROUGH a relay, because the two
peers can't reach each other yet (that's the point of punching). The relay is the
SAME announcer node that already relays PEER_HANDSHAKE in d-hyperswarm's working
connect-by-key (see [[hyperswarm-interop-project]] "Relay chain"): announce-self →
each announced-to node holds {relay: announcer-socket, record} → client sends via
that node → it forwards to the server. So `dht._router.peerHolepunch(target,
{id,payload,peerAddress,socket}, relayAddr)` = send HS_PEER_HOLEPUNCH to `relayAddr`
(a node from the lookup that returned the record) with the server's holepunch `id`;
the node forwards to the server, server's `_onpeerholepunch` replies, node relays
back. **Lean on LIVE DHT nodes to relay** (they implement the protocol) — building a
pure-D relay (blind-relay / relay-connection / router.d) is DEFERRED; not needed for
rig interop. This mirrors how connect/serve interop already works.

## Wire (all present already, Stage D)
- HS_PEER_HOLEPUNCH = 1 (messages.d). Holepunch envelope {mode,id,payload,peerAddress}
  + encode/decodeHolepunch (connect_messages.d). HolepunchPayload {error,firewall,
  round,connected,punching,addresses,remoteAddress,token,remoteToken} + codec.
- SecurePayload (secure_payload.d): encrypt/decrypt under holepunchSecret; token(addr).
- Holepuncher (holepuncher.d): updateRemote, punch, onConnect/onAbort, consistentProbe
  (with the fast-open ping fix e69337a), the RANDOM strategies, ping/openSession.
- HandshakeResult.holepunchSecret (noise_wrap.d). Rpc.request via relay already works.

## E1 — server side (serve.d)
When accepting a PEER_HANDSHAKE and the CLIENT is firewalled OR we (server) have no
reachable address (`ourRemoteAddr` null): instead of advertising firewall=OPEN +
addresses, advertise **firewall=UNKNOWN + holepunch={id, relays}** in the noise
payload (server.js L378-379), and register a half-open session:
  - `_holepunches[id]` registry (reuse a free slot; id = index). Holds: puncher
    (new Holepuncher(rpc, pool, isInitiator=false, remoteFirewall)), payload (new
    SecurePayload(holepunchSecret)), round, clearing-timeout, the accept stream.
  - `setupHolepuncher`: puncher.onConnect = bind the pre-created server stream to the
    punched socket via change_remote (Stage A binding) OR connect+secretstream; sample
    the server holder's NAT (nat.autoSample equivalent — sampleNatOn on puncher.socket).
  - Keep the OPEN shortcut (server.js L412: `if (remotePayload.firewall === OPEN ||
    direct)` → the existing direct accept path in serve.d, unchanged).
- HS_PEER_HOLEPUNCH handler `_onpeerholepunch({id, peerAddress, payload}, req)`
  (server.js L520+): look up `_holepunches[id]`; require peerAddress + h.payload;
  `remotePayload = h.payload.decrypt(payload)`; if !remotePayload return null; if error
  → set round, abort. `token = h.payload.token(peerAddress)`; `echoed = isServerRelay &&
  remoteToken == token`. If `req.socket === p.socket` → `p.nat.add(req.to, req.from)`.
  updateRemote({punching, firewall, addresses, verified: echoed?peerAddress.host:null}).
  Fast-open ping if CONSISTENT and addresses match remoteAddress (server.js L562-570).
  tryLater gate. `p.punch()`. Re-encrypt reply payload {firewall, round, punching,
  addresses: p.nat.addresses, token, remoteToken: echoed?null:token} and return it.

## E2 — client side (connect.d)
After connectHandshake, on serverPayload: `remoteHolepunchable = !!(payload.holepunch
&& payload.holepunch.relays.length)`. Branch (connect.js L221+, spec Integration line):
  - OPEN or (relayed && !remoteHolepunchable) → direct connect (DONE, existing path).
  - our OPEN → passive wait ~10s for the server to punch to us.
  - else → new Holepuncher(initiator=true) + SecurePayload(holepunchSecret); run the
    round. onsocket: if already-connected raw socket → rawStream.changeRemote; else
    connect + secretstream over the punched socket.
- Round loop (connect.js updateHolepunch/probeRound/roundPunch, ~L548-770):
  `updateHolepunch` → `_router.peerHolepunch(target, {id, payload:encrypt(payload),
  peerAddress, socket}, relayAddr)` → decrypt reply → error/TRY_LATER handling →
  updateRemote({punching,firewall,addresses,verified:echoed?peerAddress.host:null}).
  probeRound drives analyze(allowReopen) then punch; retries; tryLater(c) waits
  ~10000+rand*10000ms. HANDSHAKE_INITIAL_TIMEOUT=10000.

## E3 — onsocket / stream upgrade
puncher.onConnect(socket, port, host): the punched hole yields a udx socket + the
peer's port/host. Open (or re-home) the UDX stream to that address:
  - client: rawStream.changeRemote(socket, serverUdxId, port, host) if a raw stream
    exists, else init a udx stream on `socket` to (port,host) + run secret-stream from
    the handshake keys. hs_udx_stream_change_remote (Stage A binding) is the primitive.
  - server: bind its pre-created accept stream to the punched socket (change_remote).

## Testing / acceptance
- Unit (no net): the round handler in isolation — two SecurePayloads sharing a secret,
  feed a synthetic Holepunch payload, assert decrypt + updateRemote fields + the
  re-encrypted reply round-trips. Puncher punch() dispatch already unit-covered (D).
- Rig (photo-wagon, NO --fire-at): D client connect-by-key to a D server, both behind
  the two real NATs, relayed via live DHT nodes. The round number gives auto-sync →
  punch → secret-stream connection. If it forks, the round timing needs tightening
  (align both sides' first probe to the same round boundary, like --fire-at did).
- Keep loopback + the 58-suite green throughout.

## Order (commit per advance)
E1a: _holepunches registry + noise-payload holepunch advertisement (firewall=UNKNOWN
  + holepunch{id}) when not reachable; keep OPEN shortcut. Unit: decode the server
  payload asserts it advertises holepunch.
E1b: _onpeerholepunch handler + setupHolepuncher (server puncher lifecycle). Unit:
  synthetic round.
E2:  client holepunch branch + Holepuncher(initiator=true) + the round loop via the
  relay (Rpc.request to a relay node with HS_PEER_HOLEPUNCH).
E3:  onsocket → change_remote / connect+secretstream (both sides); the connection forms.
E-rig: live acceptance, no --fire-at.
Deferred: pure-D relay (router.d/blind-relay), the RANDOM-side live test (rig has no
symmetric NAT — unit-covered), the udx_socket_send_ttl specific-ttl-queue root fix.
