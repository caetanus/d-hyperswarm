# hyperdht holepunch → D port spec (interop-fragile; constants verbatim from ~/lab/hyperdht/lib)

Reference (ground truth): ~/lab/hyperdht/lib/{nat,holepuncher,constants,router,connect,server,messages,secure-payload,socket-pool,noise-wrap}.js + index.js.

## NEVER approximate these constants
BIRTHDAY_SOCKETS=256; beacon = single [0x00] byte (recv demux: >1 byte → dht-rpc, ==1 → puncher);
TTL low=5 / default=64; MAX_REOPENS=3; nat _minSamples=4, decision gate sampled>=3, max-hit thresholds 3/1/2;
_consistentProbe: 10 tries, 1000ms pause, unverified only every 4th tick ((tries&3)!=0 skip), responder sleeps 1000ms first;
_randomProbes: tries=1750, 20ms pause, randomPort()=[1000,65536); _keepAliveRandomNat: 100ms first, 1750 tries, 20ms, first full sweep TTL5 then 64;
random-punch gate: _randomPunchLimit=1, _randomPunchInterval=20000ms; tryLater backoff=10000+rand*10000; HANDSHAKE_INITIAL_TIMEOUT=10000; relayTimeout=15000.
coerceFirewall: OPEN→CONSISTENT else unchanged (both sides before dispatch).
firewall enum: UNKNOWN=0 OPEN=1 CONSISTENT=2 RANDOM=3.

## NAT sampler (nat.d, from nat.js)
Input: DHT PING replies (cmd PING=0) sent FROM the socket being classified → {to=our observed external, from=responder}.
add(to,from): dedup responder ref (visited==2 short-circuits); addSample(_samplesHost, host,0) + addSample(_samplesFull, host,port), both kept desc by hits.
_updateFirewall (only if sampled>=3): !firewalled→OPEN; max=_samplesFull[0].hits; max>=3→CONSISTENT; max==1→RANDOM;
  max==2: (_samplesHost.length==1 && sampled>3→RANDOM) | (_samplesHost.length>1 && _samplesFull[1].hits>1→CONSISTENT) | (sampled>4→RANDOM) | else no change.
_updateAddresses: UNKNOWN→null; RANDOM→[_samplesHost[0]] (host, port 0); CONSISTENT→_samplesFull hits>=2 (or top-2).
Requires Rpc.request(...,socket) so PING goes out a chosen pool socket (rewire g_rpcBySock).

## Holepuncher (holepuncher.d, from holepuncher.js)
holepunch(sock,addr,lowTTL)=send([0],addr,ttl=lowTTL?5:64). ping→TTL64, openSession→TTL5.
_onholepunchmessage: responder→reply holepunch(TTL64); initiator→first beacon wins: connected, release holders, onconnect(sock,port,host).
_punch dispatch (coerced): CONSISTENT×CONSISTENT→_consistentProbe(no verified); CONSISTENT×≥RANDOM→_randomProbes(verified); ≥RANDOM×CONSISTENT→_openBirthdaySockets(256)+_keepAliveRandomNat; ≥RANDOM×≥RANDOM→abort (double-random).
analyze/_reopen up to MAX_REOPENS on unstable ((remote≥RANDOM&&local≥RANDOM)||local==UNKNOWN).

## Wire: connect_messages.d confirmed BYTE-EXACT vs messages.js. Missing: SecurePayload.
SecurePayload (secure_payload.d, from secure-payload.js): holepunchPayload carried encrypted in Holepunch.payload:
  crypto_secretbox_easy, layout [24 nonce][ciphertext][16 mac]; key=holepunchSecret=generichash(NS.PEER_HOLEPUNCH, hs.hash) — ALREADY in D as HandshakeResult.holepunchSecret (noise_wrap.d:36).
  token(addr)=generichash(addr.host,_localSecret) 32B, _localSecret random per puncher.
Punch msgs: all PEER_HOLEPUNCH (mode FROM_CLIENT=0/FROM_SERVER=1/FROM_RELAY=2/FROM_SECOND_RELAY=3/REPLY=4), payload=SecurePayload(holepunchPayload), routed client↔serverRelay↔server like the handshake.

## Integration
connect.d (after handshake, on serverPayload): OPEN||(relayed&&!remoteHolepunchable)→direct connect (DONE); our OPEN→passive wait 10s; else new Holepuncher(initiator=true) probeRound→roundPunch. onsocket: connected raw→change_remote else connect+secretstream.
serve.d: no reachable remoteAddress→advertise firewall=UNKNOWN + holepunch{id,relays} (not OPEN+addr), register half-open under id, Holepuncher(initiator=false). Keep OPEN shortcut. Add HS_PEER_HOLEPUNCH handler → _onpeerholepunch (decrypt, nat.add(to,from) if socket==p.socket, updateRemote, analyze, fast-ping if CONSISTENT+match, tryLater gate, p.punch(), re-encrypt reply).
node/rpc: Rpc.request(socket=main)+g_rpcBySock reg; SocketPool on Dht (acquire/release, N sockets on rpc.udxPtr, 1-byte demux, 3s linger). Relay role (router.d) deferrable — live DHT nodes relay for client/server interop.

## UDX BLOCKERS (bind in amalgam + udx.d)
1. hs_udx_socket_send_ttl(req,s,bufs,len,addr,ttl,cb) — udx_socket_send_ttl (udx.h:599). REQUIRED (beacon). facade already has hsuv_udp_set_ttl (facade.d:668).
2. hs_udx_stream_change_remote(stream,socket,remote_id,addr,cb) + alias UdxStreamRemoteChangedCb=extern(C) void function(void*) nothrow — udx_stream_change_remote (udx.h:647). REQUIRED (onsocket upgrade).
3. hs_udx_stream_relay_to — udx.h:650. ONLY for relay role (deferrable).
Present: hs_udx_stream_firewall (accept), hsuv_udp_set_ttl.

## Staging (each independently testable)
A. udx bindings (send_ttl + change_remote) — unit, no network.
B. SocketPool + Rpc.request(socket) — live bootstrap node1/2.hyperdht.org:49737: per-socket NAT observation.
C. nat.d sampler — unit (synthetic add() per branch) + live 4-ping classification. One machine.
D. secure_payload.d + holepuncher.d core — loopback two-puncher CONSISTENT×CONSISTENT → onconnect; assert TTLs.
E. wire into connect.d/serve.d + HS_PEER_HOLEPUNCH — D↔D one host through punch path; D↔JS decrypt rounds.
F. real two-NAT interop (rig): all NAT pairs, random-punch gate, tryLater; router.d only if pure-D-relay needed.
