/// hyperswarm's top layer (index.js): join a topic and get end-to-end encrypted
/// connections to the peers sharing it. This is a thin orchestration over the
/// pieces already built — dht.lookup(topic) to discover a topic's servers and
/// dht connect-by-key to reach each one — plus connection de-duplication.
///
/// Client mode is implemented (discover a topic's servers and connect to them);
/// server mode (announce + accept) is the next step. join()'s `client`/`server`
/// options mirror the reference so callers read the same.
module hyperswarm.swarm;

import hyperswarm.dht.node : Dht;
import std.conv : to;
import hyperswarm.dht.messages : PeerRecord;
import hyperswarm.dht.connect : connectHandshake, connectHandshakeTo, connectViaHolepunch, ConnectHandshake,
    PunchResult, PunchOutcome;
import hyperswarm.dht.connect_messages : FW_OPEN;
import hyperswarm.dht.serve : Server;
import hyperswarm.connection : Connection, hsConnRead, hsConnClose, hsConnFinalize;
import hyperswarm.udx.udx;
import hyperswarm.udx.facade : uv_buf_t;
import hyperswarm.noise.stream : SecretStream;
import hyperswarm.noise.crypto : Keypair, ed25519Keypair, ed25519RandomKeypair;
import hyperswarm.cenc : Address;
import vibe.core.core : runTask, sleep;
import core.time : msecs, seconds, Duration;
import core.sys.posix.sys.socket : sockaddr, AF_INET;
import core.sys.posix.netinet.in_ : sockaddr_in;
import core.sys.posix.arpa.inet : htons, inet_addr;
import std.random : uniform;
import std.format : format;
import std.string : toStringz;

private string toHex(scope const(ubyte)[] b) nothrow
{
    string r;
    try
        foreach (x; b)
            r ~= format("%02x", x);
    catch (Exception)
    {
    }
    return r;
}

final class Hyperswarm
{
    Keypair keyPair;
    Dht dht;
    /// Cap on concurrent connections (client + server). Further peers are ignored
    /// until a slot frees; a rejoined discovery re-offers them.
    size_t maxPeers = 64;
    /// How often a server re-announces its topic and itself. A single announce at
    /// join can land while our routing table is still cold — stored at the nodes
    /// we happened to know, not the ones actually closest to the topic — so a
    /// converged client never finds it; and DHT records expire. Re-announcing
    /// re-runs the query (warming the table toward the topic) and refreshes the
    /// record, so a cold first announce self-corrects and a long-lived server
    /// stays findable. Well under any record TTL; lower it for snappier interop.
    Duration announceInterval = 30.seconds;
    private Server server;

    // The address we advertise for connections: what the DHT reports back to us
    // (reachable off-box), falling back to loopback until a node has told us.
    private Address ourUdxAddr()
    {
        auto a = dht.rpc.remoteAddress();
        return a.host.length ? a : Address("127.0.0.1", 4, dht.rpc.localPort);
    }

    // Per remote public key, the live connections to it — one PER ADDRESS: a peer
    // reached on the LAN and through its punched WAN mapping is two connections,
    // both kept (the application prefers one for new streams and migrates; a
    // content-addressed transfer resumes on the other with no loss). Identity is
    // the public key the handshake authenticated, never an address.
    private Connection[][string] connections;
    private bool[string] connecting; // in-flight connects: by key hex, or hex@host:port
    private bool[string] topics; // joined topics (hex) still in client mode
    private bool destroyed;
    // Outbound connections whose stream exists but that are not yet in `connections`
    // (dialing / waiting to open): close() destroys them before the dht socket, so a
    // pre-registration stream never leaves the socket busy (UV_EBUSY) at teardown.
    private bool[Connection] pendingOut;

    /// Invoked once per new peer connection, after its secret-stream opens.
    void delegate(Connection) nothrow onConnection;
    /// Invoked when a topic lookup first discovers a peer (before connecting).
    void delegate(ubyte[32]) nothrow onDiscover;

    /// `bootstrap` is the DHT bootstrap node list; `seed` (32 bytes) makes the
    /// key pair deterministic (empty → a random pair).
    this(Address[] bootstrap, scope const(ubyte)[] seed = null)
    {
        keyPair = seed.length == 32 ? ed25519Keypair(seed) : ed25519RandomKeypair();

        // The Dht owns the udx socket that carries both dht-rpc and our connection
        // streams (one socket, like hyperdht) — so the address a server sees our
        // handshake come from is the very socket our stream lives on.
        dht = new Dht(bootstrap);

        // Accept incoming connections (server mode is armed per-topic by join()).
        server = new Server(dht, keyPair);
        server.onConnection = (Connection c) nothrow { adoptConnection(c); };
    }

    // De-dup a server-accepted connection against the client-side map (and any
    // in-flight outbound to the same peer) and emit it; otherwise tear it down so a
    // rejected connection doesn't linger.
    private void adoptConnection(Connection c) nothrow
    {
        immutable hex = toHex(c.remotePublicKey[]);
        // A SYN accepted just before close() opens its secret-stream just after: the
        // adopt must not put it back in the registry or fire the application handler
        // once the swarm is torn down.
        if (destroyed || hasConnectionAt(hex, c.remoteAddress) || liveConnections() >= maxPeers)
        {
            c.destroy(); // closed; or the same peer at the same address is already ours; or full
            return;
        }
        keep(hex, c);
    }

    /// Every live connection to `pubkey` (LAN, WAN…), for the application to pick
    /// from. Empty when none.
    Connection[] connectionsOf(ubyte[32] pubkey) nothrow
    {
        if (auto p = toHex(pubkey[]) in connections)
            return (*p).dup;
        return null;
    }

    /// Every live connection, over every key and address — what maxPeers caps
    /// (a peer reconnecting from fresh source ports is not free).
    size_t liveConnections() const nothrow
    {
        size_t n;
        foreach (list; connections.byValue)
            n += list.length;
        return n;
    }

    private bool hasConnectionAt(string hex, Address addr) nothrow
    {
        if (auto p = hex in connections)
            foreach (c; *p)
                if (c.remoteAddress.host == addr.host && c.remoteAddress.port == addr.port)
                    return true;
        return false;
    }

    // Register a connection and announce it; on close, drop exactly that one.
    private void keep(string hex, Connection c) nothrow
    {
        pendingOut.remove(c); // promoted to a live connection
        connections[hex] ~= c;
        c.onCloseInternal = () nothrow {
            if (auto p = hex in connections)
            {
                Connection[] rest;
                foreach (x; *p)
                    if (x !is c)
                        rest ~= x;
                if (rest.length)
                    connections[hex] = rest;
                else
                    connections.remove(hex);
            }
        };
        if (onConnection !is null)
            onConnection(c);
    }

    /// Join `topic`: in client mode, discover and connect to its peers; in server
    /// mode, announce the topic and ourselves (listen) so peers can find + reach us,
    /// accepting their connections. Both emit onConnection (de-duplicated).
    void join(ubyte[32] topic, bool client = true, bool serverMode = false)
    {
        if (destroyed)
            return;
        immutable hex = toHex(topic[]);
        if (serverMode)
        {
            auto t = topic;
            // Announce the topic (so a lookup finds us) + announce-self (so the
            // connect handshake can be routed to us), and keep re-announcing so a
            // cold-table first announce self-corrects and the record stays fresh.
            runTask(() nothrow { announceLoop(t); });
        }
        if (client && (hex in topics) is null)
        {
            topics[hex] = true;
            auto t = topic;
            runTask(() nothrow { discoverLoop(t); });
        }
    }

    /// Stop discovering peers for `topic` (existing connections are kept).
    void leave(ubyte[32] topic)
    {
        topics.remove(toHex(topic[]));
    }

    void close()
    {
        destroyed = true;
        // Drain the server's half-open accepts + holepunch sessions first: they hold
        // streams/pool sockets that would otherwise make the dht socket close return
        // UV_EBUSY, and their accept tasks would call back into a torn-down swarm.
        try
            server.close();
        catch (Exception)
        {
        }
        // Destroy live connections first: libudx refuses to close a socket that
        // still owns streams, so closing the dht socket before this would leak it.
        foreach (list; connections.values)
            foreach (c; list)
                c.destroy();
        connections = null;
        // In-flight outbound streams not yet registered: destroy them too, so no
        // stream is still on the dht socket when it closes.
        foreach (c; pendingOut.keys)
            try
                c.destroy();
            catch (Exception)
            {
            }
        pendingOut = null;
        try
            dht.close();
        catch (Exception)
        {
        }
    }

    // Server mode: (re-)announce the topic and ourselves on an interval. The
    // first announce can land on a cold routing table (the wrong nodes); each
    // re-announce re-runs the query, warming toward the topic and re-storing on
    // the nodes actually closest to it, and refreshes the record before it
    // expires. Runs until the swarm is closed.
    private void announceLoop(ubyte[32] topic) nothrow
    {
        immutable ticks = cast(int)(announceInterval.total!"msecs" / 100);
        while (!destroyed)
        {
            try
            {
                server.listen(); // announce-self under BLAKE2b(publicKey)
                // The topic record's relayAddresses are the DHT nodes a client can
                // send our PEER_HANDSHAKE through (the ones the announce-self landed
                // on, which hold our router entry) — hyperdht's semantics, and what
                // lets a client skip the FIND_PEER walk. Never our own address: a
                // NAT'd node cannot be reached there.
                auto relays = server.relayAddresses(); // this loop's own listen() result
                dht.announce(topic, keyPair, relays); // topic record
            }
            catch (Exception)
            {
            }
            for (int i = 0; i < ticks && !destroyed; i++)
                try
                    sleep(100.msecs);
                catch (Exception)
                {
                }
        }
    }

    // Periodically look the topic up and connect to any newly-seen server.
    private void discoverLoop(ubyte[32] topic) nothrow
    {
        immutable hex = toHex(topic[]);
        while (!destroyed && (hex in topics) !is null)
        {
            try
            {
                // Connect on the first record the DHT returns; the walk finishes behind.
                dht.lookupEach(topic, (PeerRecord p) nothrow { handlePeer(p.publicKey, p.relayAddresses); });
            }
            catch (Exception)
            {
            }
            // The reference refreshes every ~10 min; a short interval keeps the
            // interop snappy without hammering the network.
            for (int i = 0; i < 100 && !destroyed && (hex in topics) !is null; i++)
                try
                    sleep(100.msecs);
                catch (Exception)
                {
                }
        }
    }

    // De-duplicate by remote pubkey, then connect in a fresh fiber.
    private void handlePeer(ubyte[32] pubkey, Address[] relayHints = null) nothrow
    {
        if (pubkey[] == keyPair.publicKey[])
            return;
        immutable hex = toHex(pubkey[]);
        if ((hex in connections) !is null || (hex in connecting) !is null)
            return;
        if (liveConnections() + connecting.length >= maxPeers)
            return; // at the connection cap; a later discovery re-offers this peer
        if (onDiscover !is null)
            onDiscover(pubkey);
        connecting[hex] = true;
        auto pk = pubkey;
        auto hints = relayHints.dup;
        try
            runTask(() nothrow { connectTo(pk, hints); });
        catch (Exception)
            connecting.remove(hex);
    }

    private void connectTo(ubyte[32] pubkey, Address[] relayHints = null) nothrow
    {
        immutable hex = toHex(pubkey[]);
        scope (exit)
            connecting.remove(hex);
        try
        {
            auto conn = openConnection(pubkey, relayHints);
            pendingOut[conn] = true;
            scope (exit)
                pendingOut.remove(conn);
            for (int i = 0; i < 300 && !conn.opened; i++)
                sleep(10.msecs);
            if (!conn.opened)
            {
                conn.destroy(); // gave up: tear the stream down, don't leak it
                return;
            }
            // Dedup by the ADDRESS we actually reached, not the key: a WAN dial that
            // completes while a LAN path to the same peer is already up is a second,
            // wanted connection (roaming), kept unless THIS exact endpoint is already
            // ours. And never adopt into a swarm that has since closed.
            if (destroyed || hasConnectionAt(hex, conn.remoteAddress))
            {
                conn.destroy();
                return;
            }
            keep(hex, conn);
        }
        catch (Exception)
        {
        }
    }

    // The full client connect: peer handshake, open a UDX stream to the server on
    // our shared socket, and run the connection secret-stream from the IK keys.
    /// The udx/dht socket's local port — what a LAN beacon announces so a peer on
    /// the same network can connectAt() us without any DHT round trip.
    ushort udxPort()
    {
        return dht.rpc.localPort;
    }

    /// Connect to `pubkey` at a KNOWN address (a LAN peer found by mDNS): the peer
    /// handshake goes straight to `addr` — no lookup, no relay, no punch — and the
    /// udx stream is opened to that same address, not to whatever public address the
    /// server advertises (from the LAN, its public address is the wrong side of its
    /// NAT). Fires onConnection like a DHT-found peer; de-duplicated the same way.
    void connectAt(ubyte[32] pubkey, Address addr) nothrow
    {
        if (destroyed || pubkey[] == keyPair.publicKey[])
            return;
        immutable hex = toHex(pubkey[]);
        immutable key = hex ~ "@" ~ addr.host ~ ":" ~ to!string(addr.port);
        // Another connection to this peer at ANOTHER address is no reason to skip:
        // a LAN path found while the WAN one still lives is opened right away and
        // both stay up (roaming). Only the same address, or a dial to it in flight.
        if (hasConnectionAt(hex, addr) || (key in connecting) !is null)
        {
            import vibe.core.log : logInfo;
            logInfo("hyperswarm: connectAt %s:%s skipped (%s)", addr.host, addr.port,
                hasConnectionAt(hex, addr) ? "already connected at this address" : "connect to it in flight");
            return;
        }
        if (liveConnections() + connecting.length >= maxPeers)
            return; // the cap counts connections, not keys: a second path is not free
        if (onDiscover !is null && hex !in connections)
            onDiscover(pubkey);
        connecting[key] = true;
        auto pk = pubkey;
        try
            runTask(() nothrow {
                scope (exit)
                    connecting.remove(key);
                try
                {
                    immutable uint ourUdxId = cast(uint) uniform(1, uint.max);
                    auto ch = connectHandshakeTo(dht, pk, keyPair, addr, ourUdxAddr, ourUdxId);
                    auto conn = openStreamTo(ch, addr, ourUdxId);
                    pendingOut[conn] = true;
                    scope (exit)
                        pendingOut.remove(conn);
                    adoptOutbound(hex, conn);
                }
                catch (Exception e)
                {
                    import vibe.core.log : logInfo;
                    logInfo("hyperswarm: connectAt %s:%s failed: %s", addr.host, addr.port, e.msg);
                }
            });
        catch (Exception)
            connecting.remove(key);
    }

    // The udx stream + secret-stream over a completed handshake, aimed at `target`.
    private Connection openStreamTo(ConnectHandshake ch, Address target, uint ourUdxId)
    {
        auto stream = new ubyte[](hs_udx_sizeof_stream());
        hs_udx_stream_init(dht.rpc.udxPtr, stream.ptr, ourUdxId, &hsConnClose, &hsConnFinalize);
        hs_udx_stream_read_start(stream.ptr, &hsConnRead);
        auto ss = SecretStream.fromHandshake(true, ch.hs.tx, ch.hs.rx, ch.hs.hash,
            ch.hs.remotePublicKey);
        auto conn = new Connection(dht.rpc.udxPtr, stream.ptr, ss, ch.hs.remotePublicKey);
        conn.remoteAddress = target;
        sockaddr_in peer;
        peer.sin_family = AF_INET;
        peer.sin_addr.s_addr = inet_addr(target.host.toStringz);
        peer.sin_port = htons(target.port);
        hs_udx_stream_connect(stream.ptr, dht.rpc.sockPtr, ch.serverPayload.udx.id, cast(sockaddr*)&peer);
        conn.start(); // secret-stream setup frame
        return conn;
    }

    // Wait for the secret-stream to open, then register + announce, unless a
    // connection to the same peer at the same address won meanwhile.
    private void adoptOutbound(string hex, Connection conn)
    {
        for (int i = 0; i < 300 && !conn.opened; i++)
            sleep(10.msecs);
        if (!conn.opened)
        {
            conn.destroy(); // gave up: tear the stream down, don't leak it
            return;
        }
        if (destroyed || hasConnectionAt(hex, conn.remoteAddress))
        {
            conn.destroy(); // closed meanwhile, or an inbound over this path won the race
            return;
        }
        keep(hex, conn);
    }

    private Connection openConnection(ubyte[32] pubkey, Address[] relayHints = null)
    {
        // A NAT'd peer (CGNAT/4G — the whole point) can't be reached by a direct dial,
        // so the ONE handshake advertises our firewall as unknown: if the server offers
        // a holepunch, connectViaHolepunch runs it and returns the connection over the
        // punched socket; if it offers none it is directly reachable and we dial it
        // from that same handshake. A punch that was tried and failed is a failure —
        // never a second handshake claiming we are OPEN when we are not.
        immutable uint ourUdxId = cast(uint) uniform(1, uint.max);
        auto r = connectViaHolepunch(dht, pubkey, keyPair, ourUdxAddr, ourUdxId,
            3.seconds, 30.seconds, relayHints);
        final switch (r.outcome)
        {
        case PunchOutcome.punched:
            return r.conn;
        case PunchOutcome.failed:
            throw new Exception("hyperswarm: holepunch failed");
        case PunchOutcome.direct:
            break;
        }
        auto ch = r.handshake;

        auto stream = new ubyte[](hs_udx_sizeof_stream());
        hs_udx_stream_init(dht.rpc.udxPtr, stream.ptr, ourUdxId, &hsConnClose, &hsConnFinalize);
        hs_udx_stream_read_start(stream.ptr, &hsConnRead);

        auto ss = SecretStream.fromHandshake(true, ch.hs.tx, ch.hs.rx, ch.hs.hash,
            ch.hs.remotePublicKey);
        auto conn = new Connection(dht.rpc.udxPtr, stream.ptr, ss, ch.hs.remotePublicKey);

        // Reach the server at the address it advertised in its noisePayload (its
        // real udx socket), falling back to the handshake's serverAddress. In the
        // relayed case serverAddress is the relay node, not the server.
        auto target = ch.serverPayload.addresses4.length ? ch.serverPayload.addresses4[0]
            : ch.serverAddress;
        conn.remoteAddress = target;
        sockaddr_in peer;
        peer.sin_family = AF_INET;
        peer.sin_addr.s_addr = inet_addr(target.host.toStringz);
        peer.sin_port = htons(target.port);
        hs_udx_stream_connect(stream.ptr, dht.rpc.sockPtr, ch.serverPayload.udx.id, cast(sockaddr*)&peer);

        conn.start(); // secret-stream setup frame
        return conn;
    }
}
