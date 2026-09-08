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
import hyperswarm.dht.connect_messages : Handshake, NoisePayload, UdxInfo, FW_OPEN,
    encodeHandshake, decodeHandshake;
import hyperswarm.dht.messages : HS_PEER_HANDSHAKE;
import hyperswarm.dht.wire : RequestPacket, encodeReply, encodeRequest;
import hyperswarm.connection : Connection, hsConnRead, hsConnClose, hsConnFinalize;
import hyperswarm.udx.udx;
import hyperswarm.noise.stream : SecretStream;
import hyperswarm.noise.crypto : Keypair, keyedBlake2b;
import hyperswarm.cenc : Address;
import vibe.core.core : runTask, sleep;
import core.time : seconds;
import std.random : uniform;

// Cap on half-open (handshaked but not yet SYN'd) incoming streams, and how long
// one may sit before we tear it down — bounds a flood of handshakes with no SYN.
private enum size_t MAX_PENDING = 512;
private enum HANDSHAKE_WAIT = 10;

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
}

private __gshared Incoming[void*] g_incoming;

// A client's SYN reached an unconnected server stream: bind it to the client's udx
// id + the SYN's source address, send our secret-stream setup frame, and accept.
extern (C) int hsServerFirewall(void* stream, void* socket, const(void)* from) nothrow
{
    auto inc = stream in g_incoming;
    if (inc is null)
        return 1; // reject: not a stream we're expecting
    immutable clientUdxId = inc.clientUdxId;
    auto conn = inc.conn;
    g_incoming.remove(stream); // connected now — no longer a pending accept
    hs_udx_stream_connect(stream, socket, clientUdxId, from);
    conn.start(); // our secret-stream setup frame
    return 0; // accept
}

/// A connect-by-key server: install it on a Dht + key pair and it answers incoming
/// peer handshakes, emitting a Connection per accepted peer.
final class Server
{
    private Dht dht;
    private Keypair keyPair;
    void delegate(Connection) nothrow onConnection;

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
        return dht.announce(target, keyPair, [ourUdxAddr]);
    }

    private void onRequest(RequestPacket req, Address from) nothrow
    {
        if (req.command != HS_PEER_HANDSHAKE || req.value.length == 0)
            return;
        try
            handlePeerHandshake(req, from);
        catch (Exception)
        {
        }
    }

    private void handlePeerHandshake(RequestPacket req, Address from)
    {
        auto env = decodeHandshake(req.value);
        if (env.noise.length == 0)
            return;
        if (g_incoming.length >= MAX_PENDING)
            return; // too many half-open handshakes waiting for a SYN — drop this

        // IK responder: consume the client's msg1 (+ its noisePayload), send msg2.
        auto wrap = new NoiseWrap(keyPair, null);
        auto clientPayload = wrap.recv(env.noise);

        immutable uint serverUdxId = cast(uint) uniform(1, uint.max);
        NoisePayload p;
        p.firewall = FW_OPEN;
        p.addresses4 = [ourUdxAddr];
        p.hasUdx = true;
        p.udx = UdxInfo(1, false, serverUdxId, 0);
        p.hasSecretStream = true;
        auto msg2 = wrap.send(p);
        auto result = wrap.finish();

        // A udx stream that accepts the client's incoming SYN via the firewall cb.
        auto stream = new ubyte[](hs_udx_sizeof_stream());
        hs_udx_stream_init(dht.rpc.udxPtr, stream.ptr, serverUdxId, &hsConnClose, &hsConnFinalize);
        hs_udx_stream_firewall(stream.ptr, &hsServerFirewall);
        hs_udx_stream_read_start(stream.ptr, &hsConnRead);

        auto ss = SecretStream.fromHandshake(false, result.tx, result.rx, result.hash,
            result.remotePublicKey);
        auto conn = new Connection(dht.rpc.udxPtr, stream.ptr, ss, result.remotePublicKey);
        auto cb = onConnection;
        conn.onOpen = () nothrow {
            if (cb !is null)
                cb(conn);
        };
        g_incoming[stream.ptr] = Incoming(clientPayload.udx.id, conn);

        // If the client never sends its SYN, tear the half-open stream down so a
        // flood of handshakes can't pin streams + state forever.
        auto sp = stream.ptr;
        runTask(() nothrow {
            try
                sleep(HANDSHAKE_WAIT.seconds);
            catch (Exception)
            {
            }
            if ((sp in g_incoming) !is null)
            {
                g_incoming.remove(sp);
                conn.destroy();
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
