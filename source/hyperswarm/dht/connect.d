/// The client side of connect-by-key (lib/connect.js + lib/router.js), handshake
/// step: find the peer via the DHT, run the Noise IK peer handshake through a relay
/// node with PEER_HANDSHAKE, and derive the connection keys + the server's address
/// and udx info. Opening the UDX stream + secret-stream (direct, then holepunch) is
/// the next step.
module hyperswarm.dht.connect;

import hyperswarm.dht.node : Dht;
import hyperswarm.dht.table : Node;
import hyperswarm.dht.noise_wrap : NoiseWrap, HandshakeResult;
import hyperswarm.dht.connect_messages : Handshake, NoisePayload, UdxInfo, FW_OPEN,
    encodeHandshake, decodeHandshake;
import hyperswarm.dht.messages : HS_FIND_PEER, HS_PEER_HANDSHAKE;
import hyperswarm.noise.crypto : keyedBlake2b, Keypair;
import hyperswarm.cenc : Address;
import std.random : uniform;
import core.time : Duration, seconds;

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
}

/// Run the peer handshake for connect(publicKey): find a relay via FIND_PEER, send a
/// PEER_HANDSHAKE carrying the IK msg1 + our noisePayload, and complete the handshake
/// from the server's reply.
ConnectHandshake connectHandshake(Dht dht, ubyte[32] publicKey, Keypair keyPair, Duration per = 3.seconds)
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

    // IK handshake (initiator knows the server's static key) carrying our connect info
    auto wrap = new NoiseWrap(keyPair, publicKey[]);
    immutable ourUdxId = cast(uint) uniform(1, uint.max);
    NoisePayload p;
    p.firewall = FW_OPEN;
    p.addresses4 = [Address("127.0.0.1", 4, dht.localPort)];
    p.hasUdx = true;
    p.udx = UdxInfo(1, false, ourUdxId, 0);
    p.hasSecretStream = true;
    auto msg1 = wrap.send(p);

    Handshake env;
    env.mode = FROM_CLIENT;
    env.noise = msg1;
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
    return ConnectHandshake(result, serverAddress, serverPayload, ourUdxId);
}
