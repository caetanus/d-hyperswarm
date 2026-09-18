/// The client side of connect-by-key (lib/connect.js + lib/router.js), handshake
/// step: find the peer via the DHT, run the Noise IK peer handshake through a relay
/// node with PEER_HANDSHAKE, and derive the connection keys + the server's address
/// and udx info. The caller then opens a UDX stream to serverAddress and runs
/// secret-stream from these keys — for a reachable (OPEN) peer that completes the
/// connection directly (no holepunch); see interop/dht-connect for the full path.
module hyperswarm.dht.connect;

import hyperswarm.dht.node : Dht;
import hyperswarm.dht.table : Node;
import hyperswarm.dht.noise_wrap : NoiseWrap, HandshakeResult;
import hyperswarm.dht.connect_messages : Handshake, NoisePayload, UdxInfo, Holepunch,
    FW_OPEN, FW_UNKNOWN, encodeHandshake, decodeHandshake, encodeHolepunch, decodeHolepunch;
import hyperswarm.dht.holepunch_session : HolepunchSession;
import hyperswarm.dht.messages : HS_FIND_PEER, HS_PEER_HANDSHAKE, HS_PEER_HOLEPUNCH;
import hyperswarm.noise.crypto : keyedBlake2b, Keypair;
import hyperswarm.noise.stream : SecretStream;
import hyperswarm.connection : Connection, hsConnRead, hsConnClose, hsConnFinalize;
import hyperswarm.udx.udx;
import hyperswarm.cenc : Address;
import core.time : Duration, seconds;
import core.sys.posix.sys.socket : sockaddr, AF_INET;
import core.sys.posix.netinet.in_ : sockaddr_in;
import core.sys.posix.arpa.inet : htons, inet_pton;
import std.string : toStringz;

// handshake relay modes (lib/router.js)
enum uint FROM_CLIENT = 0;
enum uint REPLY = 4;

/// Result of the connect handshake: the connection keys and the peer's connect info.
struct ConnectHandshake
{
    HandshakeResult hs;
    Address serverAddress;
    NoisePayload serverPayload;
    uint ourUdxId;
    Address relayAddress; // the node that relayed the handshake — reused for PEER_HOLEPUNCH
}

/// Run the peer handshake for connect(publicKey): find a relay via FIND_PEER, send a
/// PEER_HANDSHAKE carrying the IK msg1 + our noisePayload, and complete the handshake
/// from the server's reply.
ConnectHandshake connectHandshake(Dht dht, ubyte[32] publicKey, Keypair keyPair,
    Address ourAddress, uint ourUdxId, Duration per = 3.seconds,
    uint ourFirewall = FW_OPEN, Address[] ourAddresses = null)
{
    ubyte[32] target;
    keyedBlake2b(target[], publicKey[], []); // target = BLAKE2b(publicKey)

    // find the relay/server: a node that returns the announced record, else closest.
    auto replies = dht.query(target, HS_FIND_PEER, null, false, 20, per);
    Node relay;
    bool haveRelay;
    foreach (q; replies)
        if (q.value.length)
        {
            relay = q.from;
            haveRelay = true;
            break;
        }
    if (!haveRelay && replies.length)
    {
        relay = replies[0].from;
        haveRelay = true;
    }
    if (!haveRelay)
        throw new Exception("connect: peer not found");

    // IK handshake (initiator knows the server's static key) carrying our connect info.
    // ourFirewall/ourAddresses default to OPEN + [ourAddress] (the direct path); a
    // firewalled client samples its NAT first and passes the real verdict so the
    // server advertises holepunch instead of the OPEN shortcut.
    auto wrap = new NoiseWrap(keyPair, publicKey[]);
    NoisePayload p;
    p.firewall = ourFirewall;
    p.addresses4 = ourAddresses.length ? ourAddresses : [ourAddress];
    p.hasUdx = true;
    p.udx = UdxInfo(1, false, ourUdxId, 0);
    p.hasSecretStream = true;
    auto msg1 = wrap.send(p);

    Handshake env;
    env.mode = FROM_CLIENT;
    env.noise = msg1;
    // Our dht-rpc and udx streams live on SEPARATE sockets (hyperdht uses one).
    // req.from would point the server at our RPC socket; tell it our real udx
    // address via peerAddress so its OPEN-path connect reaches our facade socket.
    env.hasPeerAddress = true;
    env.peerAddress = ourAddress;
    auto reply = dht.rpc.request(Address(relay.host, 4, relay.port), HS_PEER_HANDSHAKE,
        target[], encodeHandshake(env), null, false, per);

    if (reply.value.length == 0)
        throw new Exception("connect: empty handshake reply");
    auto rhs = decodeHandshake(reply.value);
    if (rhs.mode != REPLY || rhs.noise.length == 0)
        throw new Exception("connect: bad handshake reply");

    auto serverPayload = wrap.recv(rhs.noise);
    auto result = wrap.finish();
    Address serverAddress = rhs.hasPeerAddress ? rhs.peerAddress : Address(relay.host, 4, relay.port);
    return ConnectHandshake(result, serverAddress, serverPayload, ourUdxId,
        Address(relay.host, 4, relay.port));
}

/// Connect directly to a server at a known address (skip FIND_PEER): send the
/// PEER_HANDSHAKE straight to `serverAddr`. Used for a direct connect on a LAN /
/// localhost where the peer's address is already known (no DHT discovery/relay).
ConnectHandshake connectHandshakeTo(Dht dht, ubyte[32] publicKey, Keypair keyPair,
    Address serverAddr, Address ourAddress, uint ourUdxId, Duration per = 3.seconds)
{
    ubyte[32] target;
    keyedBlake2b(target[], publicKey[], []); // target = BLAKE2b(publicKey)

    auto wrap = new NoiseWrap(keyPair, publicKey[]);
    NoisePayload p;
    p.firewall = FW_OPEN;
    p.addresses4 = [ourAddress];
    p.hasUdx = true;
    p.udx = UdxInfo(1, false, ourUdxId, 0);
    p.hasSecretStream = true;
    auto msg1 = wrap.send(p);

    Handshake env;
    env.mode = FROM_CLIENT;
    env.noise = msg1;
    auto reply = dht.rpc.request(serverAddr, HS_PEER_HANDSHAKE, target[],
        encodeHandshake(env), null, false, per);

    if (reply.value.length == 0)
        throw new Exception("connect: empty handshake reply");
    auto rhs = decodeHandshake(reply.value);
    if (rhs.mode != REPLY || rhs.noise.length == 0)
        throw new Exception("connect: bad handshake reply");

    auto serverPayload = wrap.recv(rhs.noise);
    auto result = wrap.finish();
    return ConnectHandshake(result, serverAddr, serverPayload, ourUdxId, serverAddr);
}

/// Run the client PEER_HOLEPUNCH round loop for a holepunchable server (its noise
/// payload had hasHolepunch). Port of connect.js probeRound/roundPunch, simplified to
/// the CONSISTENT path (analyze/reopen, TRY_LATER and the random-punch gate deferred):
///   - a probe round (punching=false) to exchange NAT state through the relay,
///   - once we know the server's verdict, a punch round (punching=true) so the server
///     punches with us, then p.punch() locally.
/// The rounds carry the same round number both ways, giving the simultaneity that
/// `--fire-at` faked. `session` is a HolepunchSession(isInitiator=true) whose puncher
/// has already sample()d. onConnect (wired by the caller, E3) fires on success.
void connectHolepunch(Dht dht, HolepunchSession session, ConnectHandshake ch,
    ubyte[32] target, Address ourExternal, Duration per = 3.seconds)
{
    auto p = session.puncher;
    immutable id = ch.serverPayload.holepunch.id;
    immutable relayAddr = ch.relayAddress;
    immutable serverAddr = ch.serverAddress;

    bool sendRound(bool punching)
    {
        if (p.connected || p.destroyed)
            return false;
        Holepunch env;
        env.mode = FROM_CLIENT;
        env.id = id;
        env.hasPeerAddress = true;
        env.peerAddress = ourExternal; // our external, so the server can aim back
        env.payload = session.buildClientRound(serverAddr, punching);
        try
        {
            auto reply = dht.rpc.request(relayAddr, HS_PEER_HOLEPUNCH, target[],
                encodeHolepunch(env), null, false, per);
            if (reply.value.length == 0)
                return false;
            auto rEnv = decodeHolepunch(reply.value);
            return session.applyReply(rEnv.payload, reply.to, relayAddr);
        }
        catch (Exception)
            return false;
    }

    // Probe rounds: exchange NAT state until we've learned the server's verdict.
    foreach (_; 0 .. 4)
    {
        if (!sendRound(false))
            return;
        if (p.remoteFirewall != FW_UNKNOWN && p.remoteAddresses.length)
            break;
    }
    if (p.remoteFirewall == FW_UNKNOWN || !p.remoteAddresses.length)
        return; // never converged — abort

    // Punch round: tell the server we're punching, then punch (the round number aligns
    // both sides, so neither is the nf_nat second-mover).
    sendRound(true);
    p.punch();
}

/// E3 (client side): the hole is open — form the connection over the punched socket.
/// Mirrors the OPEN client path (interop/dht-connect) but on `punchedSocket` to the
/// punched `peer` address (from puncher.onConnect) instead of the advertised server
/// address. Opens a UDX stream to the server's udx id, runs the initiator secret-
/// stream from the handshake keys, and returns the Connection (its onOpen fires once
/// the secret-stream handshake completes over the hole).
Connection formPunchedConnection(Dht dht, void* punchedSocket, Address peer, ConnectHandshake ch)
{
    auto stream = new ubyte[](hs_udx_sizeof_stream());
    hs_udx_stream_init(dht.rpc.udxPtr, stream.ptr, ch.ourUdxId, &hsConnClose, &hsConnFinalize);
    hs_udx_stream_read_start(stream.ptr, &hsConnRead);

    auto ss = SecretStream.fromHandshake(true, ch.hs.tx, ch.hs.rx, ch.hs.hash,
        ch.hs.remotePublicKey);
    auto conn = new Connection(dht.rpc.udxPtr, stream.ptr, ss, ch.hs.remotePublicKey);

    sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(peer.port);
    inet_pton(AF_INET, peer.host.toStringz, &sa.sin_addr);
    hs_udx_stream_connect(stream.ptr, punchedSocket, ch.serverPayload.udx.id, cast(sockaddr*)&sa);

    conn.start(); // our secret-stream setup frame, over the punched hole
    return conn;
}

/// High-level connect-by-key over a holepunch (ties E2 + E3): sample our NAT, run the
/// handshake advertising our real firewall, and — if the server is holepunchable —
/// run the round loop and form the connection over the hole. Returns the Connection,
/// or null if the server is directly reachable (caller uses the OPEN path) or the
/// punch times out. Automatic sync (the round number) replaces --fire-at.
Connection connectViaHolepunch(Dht dht, ubyte[32] publicKey, Keypair keyPair,
    Address ourAddress, uint ourUdxId, Duration per = 3.seconds,
    Duration punchTimeout = 30.seconds)
{
    import hyperswarm.dht.holepuncher : Holepuncher;
    import hyperswarm.dht.secure_payload : SecurePayload;
    import vibe.core.core : sleep;
    import core.time : msecs;

    ubyte[32] target;
    keyedBlake2b(target[], publicKey[], []);

    // Sample our NAT first, so the handshake advertises our real firewall + address
    // (which makes the server advertise holepunch instead of the OPEN shortcut).
    auto puncher = new Holepuncher(dht.rpc, dht.pool, /*isInitiator*/ true, FW_UNKNOWN);
    puncher.sample(dht.bootstrap);

    auto ch = connectHandshake(dht, publicKey, keyPair, ourAddress, ourUdxId, per,
        puncher.localFirewall, puncher.nat.addresses);

    if (!ch.serverPayload.hasHolepunch)
    {
        puncher.destroy();
        return null; // server is directly reachable — caller takes the OPEN path
    }

    // The hole opening fires onConnect(punchedSocket, peer); form the connection there.
    Connection conn;
    puncher.onConnect = (void* sock, Address peer) nothrow {
        try
            conn = formPunchedConnection(dht, sock, peer, ch);
        catch (Exception)
        {
        }
    };

    puncher.remoteFirewall = ch.serverPayload.firewall;
    auto session = new HolepunchSession(puncher, new SecurePayload(ch.hs.holepunchSecret));

    auto ourExternal = puncher.nat.addresses.length ? puncher.nat.addresses[0] : ourAddress;
    connectHolepunch(dht, session, ch, target, ourExternal, per); // rounds + punch()

    immutable steps = cast(int)(punchTimeout.total!"msecs" / 100);
    foreach (_; 0 .. steps)
    {
        if (conn !is null)
            break;
        sleep(100.msecs);
    }
    return conn; // null on timeout
}
