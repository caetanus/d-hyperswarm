/// The client side of connect-by-key (lib/connect.js + lib/router.js), handshake
/// step: find the peer via the DHT, run the Noise IK peer handshake through a relay
/// node with PEER_HANDSHAKE, and derive the connection keys + the server's address
/// and udx info. The caller then opens a UDX stream to serverAddress and runs
/// secret-stream from these keys — for a reachable (OPEN) peer that completes the
/// connection directly (no holepunch); see interop/dht-connect for the full path.
module hyperswarm.dht.connect;

import hyperswarm.dht.node : Dht;
import hyperswarm.dht.table : Node;
import hyperswarm.dht.wire : Reply;
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
import core.time : Duration, MonoTime, seconds;
import core.sys.posix.sys.socket : sockaddr, AF_INET;
import core.sys.posix.netinet.in_ : sockaddr_in;
import core.sys.posix.arpa.inet : htons, inet_pton;
import std.string : toStringz;
import std.algorithm.comparison : min;
import core.stdc.stdio : fprintf, stderr;
import hyperswarm.dht.rpc : g_hsTrace;

private void trace(string msg) nothrow
{
    if (g_hsTrace)
        fprintf(stderr, "HSTRACE punch: %.*s\n", cast(int) msg.length, msg.ptr);
}
private string addrStr(Address a) nothrow
{
    import std.conv : to;
    try return a.host ~ ":" ~ a.port.to!string; catch (Exception) return "?";
}

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
/// `relayHints`: DHT nodes the peer is known to have announced through (the
/// relayAddresses of its topic record) — the handshake goes straight through them,
/// and the FIND_PEER walk runs only if none of them answers (hyperdht's connect
/// with `nodes`). Saves the whole second DHT walk, ~half the time to connect.
ConnectHandshake connectHandshake(Dht dht, ubyte[32] publicKey, Keypair keyPair,
    Address ourAddress, uint ourUdxId, Duration per = 3.seconds,
    uint ourFirewall = FW_OPEN, Address[] ourAddresses = null, Address[] relayHints = null)
{
    ubyte[32] target;
    keyedBlake2b(target[], publicKey[], []); // target = BLAKE2b(publicKey)
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
    // No peerAddress from the client: the relay stamps our address on the forwarded
    // handshake (lib/router.js FROM_RELAY), and a direct server takes req.from — our
    // rpc socket, which is also our udx socket, as in hyperdht.
    // The same msg1 may be offered to several nodes in turn (the Noise state is
    // only advanced by the reply we accept).
    Address relay;
    Reply reply;
    bool answered;
    // Relay hints come from the peer's signed record — untrusted. At most three
    // plausible ones, all asked at once (one `per` of wall-clock, not one per hint),
    // the first non-empty reply wins and the rest are cancelled. A record full of
    // dead addresses therefore costs one timeout before the FIND_PEER walk.
    Address[] hints;
    foreach (h; relayHints)
        if (h.host.length && h.port != 0 && hints.length < 3)
            hints ~= h;
    if (hints.length)
    {
        import vibe.core.core : runTask, Task;
        import vibe.core.sync : createManualEvent;

        auto ev = createManualEvent();
        size_t left = hints.length;
        Task[] tasks;
        foreach (hint; hints)
            tasks ~= runTask((Address hint) nothrow {
                void done() nothrow
                {
                    left--;
                    try
                        ev.emit();
                    catch (Exception)
                    {
                    }
                }
                scope (exit)
                    done();
                try
                {
                    auto r = dht.rpc.request(hint, HS_PEER_HANDSHAKE, target[], encodeHandshake(env), null, false, per);
                    if (r.value.length && !answered)
                    {
                        reply = r;
                        relay = hint;
                        answered = true;
                    }
                }
                catch (Exception)
                {
                }
            }, hint);
        scope (exit)
            foreach (t; tasks)
                if (t.running)
                    t.interrupt(); // losers (and everything on an interrupt of us)
        while (!answered && left > 0)
        {
            auto ec = ev.emitCount;
            ev.wait(ec);
        }
    }
    if (!answered)
    {
        // find the relay/server: a node that returns the announced record, else closest.
        auto replies = dht.query(target, HS_FIND_PEER, null, false, 20, per);
        Node[] candidates;
        foreach (q; replies)
            if (q.value.length)
                candidates ~= q.from;
        foreach (q; replies)
            if (!q.value.length)
                candidates ~= q.from;
        if (!candidates.length)
            throw new Exception("connect: peer not found");
        foreach (n; candidates[0 .. min(3, $)])
        {
            try
            {
                reply = dht.rpc.request(Address(n.host, 4, n.port), HS_PEER_HANDSHAKE, target[],
                    encodeHandshake(env), null, false, per);
                if (reply.value.length)
                {
                    relay = Address(n.host, 4, n.port);
                    answered = true;
                    break;
                }
            }
            catch (Exception)
            {
            }
        }
        if (!answered)
            throw new Exception("connect: no relay answered the handshake");
    }
    auto rhs = decodeHandshake(reply.value);
    if (rhs.mode != REPLY || rhs.noise.length == 0)
        throw new Exception("connect: bad handshake reply");

    auto serverPayload = wrap.recv(rhs.noise);
    auto result = wrap.finish();
    Address serverAddress = rhs.hasPeerAddress ? rhs.peerAddress : relay;
    return ConnectHandshake(result, serverAddress, serverPayload, ourUdxId, relay);
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

/// The client PEER_HOLEPUNCH rounds — lib/connect.js probeRound + roundPunch.
/// Every round is one request through a relay NODE: `peerAddress` names the SERVER
/// (the relay forwards there, stamping our address on the way, and the server's
/// FROM_SERVER answer comes back as our reply). The server told us, in its noise
/// payload, which nodes hold its mapping (holepunch.relays); we prefer the one we
/// handshaked through. Rounds go out from the punch socket, so each reply's `to`
/// is that socket's mapping as the relay saw it (a NAT sample). Sequence:
///   probe   — openSession(server) at low TTL, send our NAT state (punching=false),
///             learn the server's state + its token for us, and where its punch
///             socket sits (the reply's peerAddress);
///   punch   — send punching=true with our token for the server and its token
///             echoed, then punch() locally while the server punches toward us.
/// Returns true when the punch strategy started (the hole itself lands in
/// puncher.onConnect); the TRY_LATER back-off of a random-NAT punch is honoured
/// by waiting and re-sending.
bool connectHolepunch(Dht dht, HolepunchSession session, ConnectHandshake ch,
    ubyte[32] target, Duration per = 3.seconds)
{
    import hyperswarm.dht.connect_messages : RelayInfo, FW_RANDOM;
    import vibe.core.core : sleep;
    import core.time : msecs;
    import std.random : uniform;

    auto p = session.puncher;
    immutable id = ch.serverPayload.holepunch.id;
    auto serverAddress = ch.serverAddress;
    // The server's relay: the one we handshaked through if it is among the nodes the
    // server announced to, else its first; with none listed, the handshake pair.
    RelayInfo serverRelay = RelayInfo(ch.relayAddress, ch.serverAddress);
    bool matched;
    foreach (r; ch.serverPayload.holepunch.relays)
        if (r.relayAddress == ch.relayAddress)
        {
            serverRelay = r;
            matched = true;
            break;
        }
    // No advertised relay is the one we handshaked through (a stale/rotated relay):
    // fall back to the server's FIRST advertised relay, as hyperdht's connect.js does
    // — otherwise the server never recognises the round's relay, mints no token, and a
    // random-NAT punch never gets a verified address.
    if (!matched && ch.serverPayload.holepunch.relays.length)
        serverRelay = ch.serverPayload.holepunch.relays[0];

    // One round: request via `relay`, addressed to `peer`; `punching` marks the punch
    // round. Returns the reply (ok=false on any failure).
    struct Round { HolepunchSession.RoundReply reply; Address peerAddress; }
    Round send(Address relay, Address peer, bool punching, ubyte[] token, ubyte[] remoteToken,
        Address remoteAddress)
    {
        Round out_;
        if (p.connected || p.destroyed)
            return out_;
        Holepunch env;
        env.mode = FROM_CLIENT;
        env.id = id;
        env.hasPeerAddress = true;
        env.peerAddress = peer;
        env.payload = session.buildClientRound(remoteAddress, punching, token, remoteToken);
        try
        {
            import std.conv : to;
            trace("round punching=" ~ punching.to!string ~ " via " ~ addrStr(relay) ~ " to " ~ addrStr(peer)
                ~ " remoteAddress=" ~ addrStr(remoteAddress) ~ " token=" ~ (token.length ? "yes" : "no")
                ~ " remoteToken=" ~ (remoteToken.length ? "yes" : "no"));
            auto reply = dht.rpc.request(relay, HS_PEER_HOLEPUNCH, target[], encodeHolepunch(env),
                null, false, per, p.socket());
            if (reply.value.length == 0)
            {
                trace("round reply: empty value");
                return out_;
            }
            auto rEnv = decodeHolepunch(reply.value);
            out_.reply = session.applyReply(rEnv.payload, reply.to, relay, token, peer.host);
            out_.peerAddress = rEnv.hasPeerAddress ? rEnv.peerAddress : relay;
            string ra; foreach (a; p.remoteAddresses) ra ~= a.host ~ ":" ~ a.port.to!string ~ (a.verified ? "(v) " : " ");
            trace("round reply: ok=" ~ out_.reply.ok.to!string ~ " err=" ~ out_.reply.error.to!string ~ " tryLater=" ~ out_.reply.tryLater.to!string
                ~ " serverToken=" ~ (out_.reply.token.length ? "yes" : "no") ~ " peerAddress=" ~ addrStr(out_.peerAddress)
                ~ " remoteFirewall=" ~ p.remoteFirewall.to!string ~ " remotePunching=" ~ p.remoteHolepunching.to!string
                ~ " remoteAddrs=[" ~ ra ~ "] ourNat=" ~ p.nat.firewall.to!string ~ " reply.to=" ~ addrStr(reply.to));
        }
        catch (Exception e)
        {
            trace("round failed: " ~ e.msg);
        }
        return out_;
    }

    // --- probe rounds ------------------------------------------------------------
    ubyte[] remoteToken; // the server's token for us, from its last reply
    foreach (attempt; 0 .. 3)
    {
        p.openSession(serverAddress);
        auto r = send(serverRelay.relayAddress, serverRelay.peerAddress, false, null, null, serverAddress);
        if (p.connected)
            return true; // the server's fast-open ping already reached our punch socket
        if (!r.reply.ok)
            return false;
        remoteToken = r.reply.token;
        // The server answered from its punch socket: that mapping is where we aim.
        if (serverRelay.relayAddress == ch.relayAddress && r.peerAddress != serverAddress
            && r.peerAddress.host.length)
        {
            serverAddress = r.peerAddress;
            p.openSession(serverAddress);
        }
        if (p.remoteFirewall == FW_UNKNOWN)
            sleep(300.msecs); // the server samples its NAT before replying; a short wait suffices
        if (p.remoteFirewall != FW_UNKNOWN && remoteToken.length)
            break;
    }
    if (p.connected)
        return true;
    if (p.remoteFirewall == FW_UNKNOWN || p.nat.firewall == FW_UNKNOWN)
        return false; // probe never converged
    if (p.remoteFirewall >= FW_RANDOM && p.nat.firewall >= FW_RANDOM)
        return false; // two randomising NATs: hyperdht gives up too
    p.nat.freeze();

    // --- punch round -------------------------------------------------------------
    foreach (attempt; 0 .. 4)
    {
        if (p.connected)
            return true;
        // connect.js roundPunch: a random punch takes a slot of the DHT-wide gate;
        // while the gate is busy hyperdht waits only if it has a relay-through to
        // retry over — we have none, so (like hyperdht then) this attempt is over.
        immutable isRandom = p.isRandomPunch();
        auto gate = p.randomGate();
        if (isRandom && gate !is null && gate.busy())
        {
            trace("random punch gate busy; giving up (no relay-through)");
            return false;
        }
        if (isRandom && gate !is null)
            gate.begin(); // committed to punching (decremented right after the round)
        auto r = send(ch.relayAddress, serverAddress, true, session.payload.token(serverAddress),
            remoteToken, Address.init);
        if (isRandom && gate !is null)
            gate.punches--; // the puncher's own increment takes over from here
        if (p.connected)
            return true;
        if (r.reply.tryLater)
        {
            // hyperdht 6.34 retries a TRY_LATER in delayed mode through the server's
            // relay with a relay-through token; without one it aborts. So do we.
            trace("server says TRY_LATER; no relay-through to retry over — aborting");
            return false;
        }
        if (!r.reply.ok || !p.remoteHolepunching)
            return false;
        return p.punch();
    }
    return false;
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
    conn.remoteAddress = peer;

    sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(peer.port);
    inet_pton(AF_INET, peer.host.toStringz, &sa.sin_addr);
    hs_udx_stream_connect(stream.ptr, punchedSocket, ch.serverPayload.udx.id, cast(sockaddr*)&sa);
    conn.ownSocket(dht.pool, punchedSocket); // the pool lends it; closed when the stream is gone

    conn.start(); // our secret-stream setup frame, over the punched hole
    return conn;
}

/// What connectViaHolepunch found out.
enum PunchOutcome
{
    direct, /// the server offered no holepunch: dial it directly from `handshake`
    punched, /// `conn` is up over the punched hole
    failed, /// the punch was attempted and did not open (or timed out)
}

struct PunchResult
{
    PunchOutcome outcome;
    Connection conn; /// set for `punched`
    ConnectHandshake handshake; /// the handshake that was run (valid for `direct` too)
}

/// High-level connect-by-key over a holepunch (ties E2 + E3): sample our NAT, run the
/// handshake advertising our real firewall, and — if the server is holepunchable —
/// run the round loop and form the connection over the hole. The result says which
/// of three things happened: `punched` (with the Connection), `direct` (the server
/// offered no holepunch — dial it from the returned handshake, no second handshake
/// needed) or `failed` (a punch was tried and did not open). Automatic sync (the
/// round number) replaces --fire-at. Throws if the handshake itself fails.
PunchResult connectViaHolepunch(Dht dht, ubyte[32] publicKey, Keypair keyPair,
    Address ourAddress, uint ourUdxId, Duration per = 3.seconds,
    Duration punchTimeout = 30.seconds, Address[] relayHints = null)
{
    import hyperswarm.dht.holepuncher : Holepuncher;
    import hyperswarm.dht.secure_payload : SecurePayload;
    import vibe.core.core : sleep;
    import core.time : msecs;

    ubyte[32] target;
    keyedBlake2b(target[], publicKey[], []);

    // Sample our NAT WHILE the handshake is in flight (hyperdht does the same: the
    // handshake goes out with firewall UNKNOWN, which makes the server offer the
    // punch; the rounds carry the real verdict). Waiting for the sample first cost
    // a full sampling round before the first packet to the server.
    import vibe.core.core : runTask;
    auto puncher = new Holepuncher(dht.rpc, dht.pool, /*isInitiator*/ true, FW_UNKNOWN,
        dht.randomPunchGate);
    HolepunchSession session;
    PunchResult result;
    result.outcome = PunchOutcome.failed;
    auto seeds = dht.bootstrap;
    auto sampler = runTask(() nothrow {
        try
            puncher.sample(seeds);
        catch (Exception)
        {
        } // interrupted (we stopped waiting) or no node answered: verdict stays UNKNOWN
    });
    // Whatever happens below — a handshake that throws, a punch that never opens, a
    // punched connection — the sampler is stopped and joined (it pings from the
    // holder socket) and the puncher/session destroyed. A lent holder (a punched
    // connection rides it) survives destroy() and is closed with that connection.
    void stopSampler() nothrow
    {
        if (!sampler.running)
            return;
        try
        {
            sampler.interrupt();
            sampler.join();
        }
        catch (Exception)
        {
        }
    }
    void cleanup() nothrow
    {
        stopSampler();
        if (session !is null)
            session.destroy();
        else
            puncher.destroy();
    }
    scope (exit)
        cleanup();
    auto ch = connectHandshake(dht, publicKey, keyPair, ourAddress, ourUdxId, per,
        FW_UNKNOWN, [ourAddress], relayHints);
    result.handshake = ch;
    // The rounds need our verdict + addresses (normally long sampled by now). Past
    // the deadline the sampler is cancelled and joined BEFORE any round touches the
    // Nat, so nothing mutates it under the rounds.
    immutable sampleDeadline = MonoTime.currTime + 3.seconds;
    while (sampler.running && MonoTime.currTime < sampleDeadline)
        sleep(10.msecs);
    stopSampler();
    try
    {
        import std.conv : to;
        string as; foreach (a; puncher.nat.addresses) as ~= addrStr(a) ~ " ";
        string rs; foreach (r; ch.serverPayload.holepunch.relays) rs ~= addrStr(r.relayAddress) ~ "->" ~ addrStr(r.peerAddress) ~ " ";
        trace("we advertised firewall=" ~ puncher.localFirewall.to!string ~ " addrs=[" ~ as ~ "]; server via relay "
            ~ addrStr(ch.relayAddress) ~ " at " ~ addrStr(ch.serverAddress) ~ " says firewall=" ~ ch.serverPayload.firewall.to!string
            ~ " holepunch=" ~ ch.serverPayload.hasHolepunch.to!string ~ " id=" ~ ch.serverPayload.holepunch.id.to!string ~ " relays=[" ~ rs ~ "]");
    }
    catch (Exception) {}

    if (!ch.serverPayload.hasHolepunch)
    {
        result.outcome = PunchOutcome.direct; // server is directly reachable: dial it
        return result;
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
    session = new HolepunchSession(puncher, new SecurePayload(ch.hs.holepunchSecret));

    if (!connectHolepunch(dht, session, ch, target, per)) // rounds + punch()
        return result; // failed

    immutable steps = cast(int)(punchTimeout.total!"msecs" / 100);
    foreach (_; 0 .. steps)
    {
        if (conn !is null)
            break;
        sleep(100.msecs);
    }
    if (conn !is null)
    {
        result.outcome = PunchOutcome.punched;
        result.conn = conn;
    }
    return result; // failed on timeout
}
