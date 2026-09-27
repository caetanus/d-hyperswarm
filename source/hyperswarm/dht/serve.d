/// The server side of connect-by-key (lib/server.js), direct path: respond to an
/// incoming PEER_HANDSHAKE as the Noise IK responder, then accept the client's UDX
/// stream (a udx stream with a firewall callback that binds to the client's address
/// when its SYN arrives) and run the connection secret-stream from the handshake
/// keys. This is the reachable/OPEN path — no holepunch — mirroring server.js's
/// `if (remotePayload.firewall === OPEN || direct)` shortcut.
///
/// Discovery/relay (announcing so a client finds us through the DHT) is separate;
/// this handles the handshake + connection once a PEER_HANDSHAKE reaches our socket.
module hyperswarm.dht.serve;

import hyperswarm.dht.node : Dht;
import hyperswarm.dht.noise_wrap : NoiseWrap, HandshakeResult;
import hyperswarm.dht.connect_messages : Handshake, NoisePayload, UdxInfo, HolepunchInfo,
    RelayInfo, Holepunch, FW_OPEN, FW_UNKNOWN, encodeHandshake, decodeHandshake,
    encodeHolepunch, decodeHolepunch;
import hyperswarm.dht.socket_pool : SocketPool;
import hyperswarm.dht.holepunch_session : HolepunchSession;
import hyperswarm.dht.messages : HS_PEER_HANDSHAKE, HS_PEER_HOLEPUNCH;
import hyperswarm.dht.wire : RequestPacket, encodeReply, encodeRequest;
import hyperswarm.dht.rpc : g_hsTrace, addrFromSockaddr;
import hyperswarm.connection : Connection, hsConnRead, hsConnClose, hsConnFinalize;
import hyperswarm.udx.udx;
import hyperswarm.noise.stream : SecretStream;
import hyperswarm.noise.crypto : Keypair, keyedBlake2b;
import hyperswarm.cenc : Address;
import vibe.core.core : runTask, sleep;
import core.time : msecs, seconds;
import std.random : uniform;

// Cap on half-open (handshaked but not yet SYN'd) incoming streams, and how long
// one may sit before we tear it down — bounds a flood of handshakes with no SYN.
private enum size_t MAX_PENDING = 512;
private enum HANDSHAKE_WAIT = 10;
// The punch needs several seconds of rounds + probes before the client's SYN arrives.
private enum HOLEPUNCH_WAIT = 45;

// handshake relay modes (lib/router.js)
private enum uint FROM_CLIENT = 0;
private enum uint FROM_SERVER = 1;
private enum uint FROM_RELAY = 2;
private enum uint REPLY = 4;

// Per-incoming-stream accept state, keyed by the udx stream pointer, so the C
// firewall callback can bind the stream to the client it belongs to. Cooperative
// single-threaded (one vibe thread), so no lock.
private struct Incoming
{
    uint clientUdxId;
    Connection conn;
    SocketPool pool; // to lend a punched holder to the connection that lands on it
    HolepunchSession session; // the responder puncher of this accept, to stop on the SYN
    Object owner; // the Server that registered it (g_incoming is process-global)
}

private __gshared Incoming[void*] g_incoming;

// A client's SYN reached an unconnected server stream: bind it to the client's udx
// id + the SYN's source address, send our secret-stream setup frame, and accept.
extern (C) int hsServerFirewall(void* stream, void* socket, const(void)* from) nothrow
{
    auto incp = stream in g_incoming;
    if (incp is null)
        return 1; // reject: not a stream we're expecting
    auto inc = *incp; // COPY: the AA value pointer dies at remove() below
    g_incoming.remove(stream); // connected now — no longer a pending accept
    immutable clientUdxId = inc.clientUdxId;
    auto conn = inc.conn;
    hs_udx_stream_connect(stream, socket, clientUdxId, from);
    // A SYN over a punched hole lands on a pool holder: that socket now belongs to
    // this connection (closed with it), not to the puncher's 45 s cleanup. Lend it
    // FIRST, then stop the puncher — its destroy() then cannot free the winner (the
    // stream keeps it busy) and it stops beaconing through a socket we now own.
    if (inc.pool !is null && inc.pool.owns(socket))
        conn.ownSocket(inc.pool, socket);
    if (inc.session !is null)
        inc.session.destroy(); // stop the probe/birthday fiber; idempotent with the timer
    try
        conn.remoteAddress = addrFromSockaddr(from);
    catch (Exception)
    {
    }
    conn.start(); // our secret-stream setup frame
    return 0; // accept
}

/// A connect-by-key server: install it on a Dht + key pair and it answers incoming
/// peer handshakes, emitting a Connection per accepted peer.
final class Server
{
    private Dht dht;
    private Keypair keyPair;
    private bool closed; // set by close(): no new accepts, no replies through a torn-down rpc
    void delegate(Connection) nothrow onConnection;

    // Half-open holepunch sessions, keyed by the id we advertise in the noise payload
    // (hyperdht's _holepunches). A firewalled client's PEER_HOLEPUNCH rounds route here.
    private HolepunchSession[uint] holepunches;
    private uint nextPunchId = 1;
    // The nodes our announce landed on, each with our address as it saw us — what a
    // firewalled client is told to route its PEER_HOLEPUNCH rounds through
    // (hyperdht's announcer.relays); a round arriving from one of them is trusted
    // for the token echo (isServerRelay).
    private RelayInfo[] relays;
    // Accepted streams whose secret-stream has not yet opened: after the firewall cb
    // fires they leave g_incoming but are not yet in the swarm registry, so THIS is
    // what owns them across that window — close() destroys any still here.
    private Connection[void*] accepted;

    this(Dht dht, Keypair keyPair)
    {
        this.dht = dht;
        this.keyPair = keyPair;
        dht.rpc.onRequest = &onRequest;
    }

    // The address we advertise: the DHT's view of us (reachable off-box), falling
    // back to loopback until a node reports it.
    private Address ourUdxAddr()
    {
        auto a = dht.rpc.remoteAddress();
        return a.host.length ? a : Address("127.0.0.1", 4, dht.rpc.localPort);
    }

    /// Announce ourselves under BLAKE2b(publicKey) (an announce-self / "listen"),
    /// so the nodes we announce to set a router entry pointing back at our socket
    /// and forward PEER_HANDSHAKE to us — i.e. a client can find + reach us by key.
    int listen()
    {
        ubyte[32] target;
        keyedBlake2b(target[], keyPair.publicKey[], []);
        auto res = dht.announceWith(target, keyPair, [ourUdxAddr]);
        RelayInfo[] fresh;
        foreach (r; res.relays)
        {
            fresh ~= RelayInfo(r.relay, r.observed);
            if (fresh.length == 3)
                break; // hyperdht advertises at most three
        }
        relays = fresh;
        return res.committed;
    }

    /// The DHT nodes our last announce-self landed on (our router entries): what
    /// a topic record advertises as relayAddresses. Empty until listen() succeeds.
    Address[] relayAddresses() const
    {
        Address[] outp;
        foreach (r; relays)
            outp ~= r.relayAddress;
        return outp;
    }

    /// Tear down every half-open accept and holepunch session this server holds —
    /// called by Hyperswarm.close() BEFORE the dht socket closes, so udx is not asked
    /// to close a socket a pending stream still owns and no accept task calls back
    /// into a torn-down swarm.
    void close() nothrow
    {
        closed = true; // handlers recheck this after every yield; no new accepts
        foreach (id; holepunches.keys)
        {
            try
                holepunches[id].destroy();
            catch (Exception)
            {
            }
            holepunches.remove(id);
        }
        // g_incoming is process-global (the C firewall cb keys by stream ptr across
        // all servers); destroy ONLY the accepts this server registered, or closing
        // one swarm would kill another's half-open handshake in the same process.
        foreach (k; accepted.keys)
        {
            try
                accepted[k].destroy();
            catch (Exception)
            {
            }
            accepted.remove(k);
        }
        foreach (k; g_incoming.keys)
            if (g_incoming[k].owner is this)
            {
                try
                    g_incoming[k].conn.destroy();
                catch (Exception)
                {
                }
                g_incoming.remove(k);
            }
    }

    private bool isServerRelay(Address from) const
    {
        foreach (r; relays)
            if (r.relayAddress.host == from.host && r.relayAddress.port == from.port)
                return true;
        return false;
    }

    private void onRequest(RequestPacket req, Address from) nothrow
    {
        if (closed || req.value.length == 0)
            return;
        try
        {
            if (req.command == HS_PEER_HANDSHAKE)
                runTask(() nothrow {
                    // On its own task: the handshake samples our NAT (DHT round trips)
                    // before it replies, and this callback runs inside the socket's
                    // read path, where blocking would stall the very replies it waits for.
                    try
                        handlePeerHandshake(req, from);
                    catch (Exception)
                    {
                    }
                });
            else if (req.command == HS_PEER_HOLEPUNCH)
                onpeerholepunch(req, from);
        }
        catch (Exception)
        {
        }
    }

    // A PEER_HOLEPUNCH round for one of our half-open sessions (server.js
    // _onpeerholepunch): run the round-step and send the sealed reply back the way
    // it came. A relayed round (FROM_RELAY, the normal case) is answered as a
    // FROM_SERVER *request* to the relay node — same tid, the client's address as
    // peerAddress — which the node turns into the client's reply (lib/router.js);
    // and it leaves from our PUNCH socket, so the node stamps that socket's mapping
    // on what the client gets: the address it must aim its beacons at. A direct
    // round (FROM_CLIENT, same LAN) gets a plain reply. The request itself reaches
    // our main rpc socket, so its `to` is not a sample of the punch socket
    // (viaOurSocket=false); the session sampled its own NAT off the DHT.
    private void onpeerholepunch(RequestPacket req, Address from)
    {
        auto env = decodeHolepunch(req.value);
        auto sp = env.id in holepunches;
        if (sp is null)
            return;
        auto session = *sp;
        auto reply = session.handleRound(env, req.to, from, /*viaOurSocket*/ false,
            isServerRelay(from));
        if (g_hsTrace)
        {
            import core.stdc.stdio : fprintf, stderr;
            import std.conv : to;
            auto p = session.puncher;
            string ra;
            foreach (a; p.remoteAddresses) ra ~= a.host ~ ":" ~ a.port.to!string ~ (a.verified ? "(v) " : " ");
            auto line = "HSTRACE serve round id=" ~ env.id.to!string ~ " mode=" ~ env.mode.to!string
                ~ " from relay " ~ from.host ~ ":" ~ from.port.to!string ~ " (ours=" ~ isServerRelay(from).to!string
                ~ ") peer " ~ env.peerAddress.host ~ ":" ~ env.peerAddress.port.to!string
                ~ " -> remoteFirewall=" ~ p.remoteFirewall.to!string ~ " remotePunching=" ~ p.remoteHolepunching.to!string
                ~ " remoteAddrs=[" ~ ra ~ "] ourNat=" ~ p.nat.firewall.to!string ~ " punching=" ~ p.punching.to!string
                ~ " connected=" ~ p.connected.to!string ~ " reply=" ~ (reply.isNull ? "drop" : "sent") ~ "\n";
            fprintf(stderr, "%.*s", cast(int) line.length, line.ptr);
        }
        if (reply.isNull)
            return;
        Holepunch back;
        back.payload = reply.get;
        back.hasPeerAddress = env.hasPeerAddress;
        back.peerAddress = env.peerAddress;
        if (env.mode == FROM_RELAY)
        {
            back.mode = FROM_SERVER;
            back.id = 0;
            auto pkt = encodeRequest(req.tid, from, HS_PEER_HOLEPUNCH, req.target,
                encodeHolepunch(back), null, null, false);
            dht.rpc.sendRawFrom(session.puncher.socket(), from, pkt);
        }
        else
        {
            back.mode = REPLY;
            back.id = env.id;
            dht.rpc.send(from, encodeReply(req.tid, from, null, null, null, 0, encodeHolepunch(back)));
        }
    }

    private void handlePeerHandshake(RequestPacket req, Address from)
    {
        if (closed)
            return; // the swarm closed between onRequest queuing us and now
        auto env = decodeHandshake(req.value);
        if (env.noise.length == 0)
            return;
        // The pending-accept cap is PER server: g_incoming is process-global, so
        // counting all of it would let one swarm's backlog starve another's accepts.
        size_t mine;
        foreach (v; g_incoming.byValue)
            if (v.owner is this)
                mine++;
        if (mine >= MAX_PENDING)
            return; // too many half-open handshakes waiting for a SYN — drop this

        // IK responder: consume the client's msg1 (+ its noisePayload), send msg2.
        auto wrap = new NoiseWrap(keyPair, null);
        auto clientPayload = wrap.recv(env.noise);

        immutable uint serverUdxId = cast(uint) uniform(1, uint.max);
        immutable wantHolepunch = clientPayload.firewall != FW_OPEN;

        NoisePayload p;
        p.addresses4 = [ourUdxAddr];
        p.hasUdx = true;
        p.udx = UdxInfo(1, false, serverUdxId, 0);
        p.hasSecretStream = true;

        uint punchId;
        if (wantHolepunch)
        {
            // Client is firewalled: advertise firewall=UNKNOWN + holepunch{id, relays}
            // and register a half-open session for its PEER_HOLEPUNCH rounds. The
            // relays are the nodes our announce landed on; a hyperdht client treats an
            // empty list as "cannot holepunch".
            punchId = nextPunchId++;
            p.firewall = FW_UNKNOWN;
            p.hasHolepunch = true;
            p.holepunch = HolepunchInfo(punchId, relays.dup);
        }
        else
            p.firewall = FW_OPEN;

        auto msg2 = wrap.send(p);
        auto result = wrap.finish();

        // Accept stream (both paths): udx matches the client's SYN to it by stream id
        // and fires the firewall cb, whether the SYN arrives on our main socket (OPEN)
        // or the punched holder (holepunch) — udx processes stream packets on a pool
        // socket internally, so the cb binds the stream to whichever socket it landed on.
        auto stream = new ubyte[](hs_udx_sizeof_stream());
        hs_udx_stream_init(dht.rpc.udxPtr, stream.ptr, serverUdxId, &hsConnClose, &hsConnFinalize);
        hs_udx_stream_firewall(stream.ptr, &hsServerFirewall);
        hs_udx_stream_read_start(stream.ptr, &hsConnRead);

        auto ss = SecretStream.fromHandshake(false, result.tx, result.rx, result.hash,
            result.remotePublicKey);
        auto conn = new Connection(dht.rpc.udxPtr, stream.ptr, ss, result.remotePublicKey);
        auto cb = onConnection;
        auto self = this;
        auto spo = stream.ptr;
        conn.onOpen = () nothrow {
            self.accepted.remove(spo); // opened + adopted: no longer a pre-open accept
            if (cb !is null)
                cb(conn);
        };
        // From here the accept is rooted in g_incoming (and, for a punch, holepunches).
        // Anything that throws below — session ctor, pool.acquire in sample, an encode —
        // would otherwise strand the stream and Connection with no cleanup timer.
        auto sp0 = stream.ptr;
        immutable pid0 = punchId;
        immutable wantHp0 = wantHolepunch;
        scope (failure)
        {
            g_incoming.remove(sp0);
            accepted.remove(sp0);
            if (wantHp0)
                if (auto s = pid0 in holepunches)
                {
                    (*s).destroy();
                    holepunches.remove(pid0);
                }
            try
                conn.destroy();
            catch (Exception)
            {
            }
        }
        g_incoming[stream.ptr] = Incoming(clientPayload.udx.id, conn, wantHolepunch ? dht.pool : null, null, this);
        accepted[stream.ptr] = conn; // owned until onOpen adopts it or close/cleanup destroys it

        if (wantHolepunch)
        {
            // Register the half-open session; its PEER_HOLEPUNCH rounds open the hole,
            // then the client's SYN arrives over the punched holder and the firewall cb
            // above accepts it. Sample our own external in the background so the round
            // can advertise it (hyperdht's autoSample).
            auto session = new HolepunchSession(dht.rpc, dht.pool, result.holepunchSecret,
                /*isInitiator*/ false, clientPayload.firewall, dht.randomPunchGate);
            holepunches[punchId] = session;
            if (auto ip = stream.ptr in g_incoming)
                ip.session = session; // the firewall cb stops it the moment the SYN lands
            // Sample the holder socket's mapping NOW, before the handshake reply goes
            // out: the client's first round then already gets our firewall verdict
            // and addresses, instead of an UNKNOWN that makes it wait and probe again.
            // The pings run in parallel, so this is one round trip, bounded.
            // Bounded HARD by wall clock: the client's whole handshake request times
            // out at `per` (3 s default), and several 800 ms sampling waves could
            // overrun it. Cap the pre-reply sample well under that; the first punch
            // round refines the verdict anyway.
            try
                session.sample(dht.bootstrap, 500.msecs, 1500.msecs);
            catch (Exception)
            {
            }
        }

        // The sample above yields (DHT round trips); the swarm may have closed
        // meanwhile. Do not reply through a torn-down rpc, and do not schedule a
        // timer that would fire against it — the scope(failure) unwinds the accept.
        if (closed)
            throw new Exception("server: closed while a handshake was in flight");

        // Tear the half-open accept (and any session) down if no SYN arrives — longer
        // for the holepunch path (the punch takes several seconds of rounds + probes).
        immutable waitSecs = wantHolepunch ? HOLEPUNCH_WAIT : HANDSHAKE_WAIT;
        immutable cleanupPunch = wantHolepunch;
        immutable cleanupId = punchId;
        auto sp = stream.ptr;
        runTask(() nothrow {
            try
                sleep(waitSecs.seconds);
            catch (Exception)
            {
            }
            if ((sp in g_incoming) !is null)
            {
                g_incoming.remove(sp);
                accepted.remove(sp);
                conn.destroy();
            }
            else if ((sp in accepted) !is null)
            {
                // the SYN came (the firewall callback took it out of g_incoming) but the
                // secret-stream never opened: give it one more wait, then drop it — these
                // piled up over a long uptime, never destroyed
                try
                    sleep(waitSecs.seconds);
                catch (Exception)
                {
                }
                if (auto c = sp in accepted)
                {
                    accepted.remove(sp);
                    (*c).destroy();
                }
            }
            if (cleanupPunch)
            {
                if (auto s = cleanupId in holepunches)
                {
                    (*s).destroy();
                    holepunches.remove(cleanupId);
                }
            }
        });

        // Send msg2 back the way the request came. A direct FROM_CLIENT connect gets
        // a plain REPLY. A relayed FROM_RELAY connect is relayed onward as a
        // FROM_SERVER request back to the relay (carrying the client's tid and its
        // address), which the relay turns into the client's reply (lib/router.js).
        if (env.mode == FROM_RELAY)
        {
            Handshake back;
            back.mode = FROM_SERVER;
            back.noise = msg2;
            back.hasPeerAddress = env.hasPeerAddress;
            back.peerAddress = env.peerAddress;
            dht.rpc.send(from, encodeRequest(req.tid, from, HS_PEER_HANDSHAKE, req.target,
                encodeHandshake(back), null, null, false));
        }
        else
        {
            Handshake reply;
            reply.mode = REPLY;
            reply.noise = msg2;
            dht.rpc.send(from, encodeReply(req.tid, from, null, null, null, 0, encodeHandshake(reply)));
        }
    }
}
