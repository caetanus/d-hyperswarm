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
import hyperswarm.dht.connect : connectHandshake;
import hyperswarm.dht.serve : Server;
import hyperswarm.connection : Connection, hsConnRead, hsConnClose, hsConnFinalize;
import hyperswarm.udx.udx;
import hyperswarm.udx.facade : uv_buf_t;
import hyperswarm.noise.stream : SecretStream;
import hyperswarm.noise.crypto : Keypair, ed25519Keypair, ed25519RandomKeypair;
import hyperswarm.cenc : Address;
import vibe.core.core : runTask, sleep;
import core.time : msecs;
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
    private Server server;

    // The address we advertise for connections: what the DHT reports back to us
    // (reachable off-box), falling back to loopback until a node has told us.
    private Address ourUdxAddr()
    {
        auto a = dht.rpc.remoteAddress();
        return a.host.length ? a : Address("127.0.0.1", 4, dht.rpc.localPort);
    }

    private Connection[string] connections; // by remote pubkey hex (de-dup)
    private bool[string] connecting; // in-flight connects (de-dup)
    private bool[string] topics; // joined topics (hex) still in client mode
    private bool destroyed;

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
        if ((hex in connections) !is null || (hex in connecting) !is null
            || connections.length >= maxPeers)
        {
            c.destroy();
            return;
        }
        connections[hex] = c;
        c.onClose = () nothrow { connections.remove(hex); };
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
            // announce the topic (so a lookup finds us) + announce-self (so the
            // connect handshake can be routed to us), then keep serving.
            runTask(() nothrow {
                try
                {
                    server.listen(); // announce-self under BLAKE2b(publicKey)
                    dht.announce(t, keyPair, [ourUdxAddr]); // topic record
                }
                catch (Exception)
                {
                }
            });
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
        // Destroy live connections first: libudx refuses to close a socket that
        // still owns streams, so closing the dht socket before this would leak it.
        foreach (c; connections.values)
            c.destroy();
        connections = null;
        try
            dht.close();
        catch (Exception)
        {
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
                auto peers = dht.lookup(topic);
                foreach (p; peers)
                    handlePeer(p.publicKey);
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
    private void handlePeer(ubyte[32] pubkey) nothrow
    {
        if (pubkey[] == keyPair.publicKey[])
            return;
        immutable hex = toHex(pubkey[]);
        if ((hex in connections) !is null || (hex in connecting) !is null)
            return;
        if (connections.length + connecting.length >= maxPeers)
            return; // at the connection cap; a later discovery re-offers this peer
        if (onDiscover !is null)
            onDiscover(pubkey);
        connecting[hex] = true;
        auto pk = pubkey;
        try
            runTask(() nothrow { connectTo(pk); });
        catch (Exception)
            connecting.remove(hex);
    }

    private void connectTo(ubyte[32] pubkey) nothrow
    {
        immutable hex = toHex(pubkey[]);
        scope (exit)
            connecting.remove(hex);
        try
        {
            auto conn = openConnection(pubkey);
            for (int i = 0; i < 300 && !conn.opened; i++)
                sleep(10.msecs);
            if (!conn.opened)
            {
                conn.destroy(); // gave up: tear the stream down, don't leak it
                return;
            }
            if ((hex in connections) !is null)
            {
                conn.destroy(); // an inbound connection to this peer won the race
                return;
            }
            connections[hex] = conn;
            // On close, free the slot so a later discovery can reconnect this peer.
            conn.onClose = () nothrow { connections.remove(hex); };
            if (onConnection !is null)
                onConnection(conn);
        }
        catch (Exception)
        {
        }
    }

    // The full client connect: peer handshake, open a UDX stream to the server on
    // our shared socket, and run the connection secret-stream from the IK keys.
    private Connection openConnection(ubyte[32] pubkey)
    {
        immutable uint ourUdxId = cast(uint) uniform(1, uint.max);
        auto ch = connectHandshake(dht, pubkey, keyPair, ourUdxAddr, ourUdxId);

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
        sockaddr_in peer;
        peer.sin_family = AF_INET;
        peer.sin_addr.s_addr = inet_addr(target.host.toStringz);
        peer.sin_port = htons(target.port);
        hs_udx_stream_connect(stream.ptr, dht.rpc.sockPtr, ch.serverPayload.udx.id, cast(sockaddr*)&peer);

        conn.start(); // secret-stream setup frame
        return conn;
    }
}
