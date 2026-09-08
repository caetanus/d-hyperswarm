/// hyperdht's peer-handshake wrapper (lib/noise-wrap.js): a Noise IK handshake with
/// the PEER_HANDSHAKE prologue, carrying a noisePayload in each message. On
/// completion it yields the transport keys (tx/rx) + handshake hash the connection's
/// secret-stream is built from, the peer's static key, the stream id, and the
/// holepunch secret.
module hyperswarm.dht.noise_wrap;

import hyperswarm.noise.handshake : Noise, Pattern;
import hyperswarm.noise.stream : streamId;
import hyperswarm.noise.crypto : Keypair, keyedBlake2b;
import hyperswarm.dht.connect_messages : NoisePayload, encodeNoisePayload, decodeNoisePayload;

// NS.PEER_HANDSHAKE / PEER_HOLEPUNCH = namespace('hyperswarm/dht', [0, 1]).
private __gshared ubyte[32] NS_PEER_HANDSHAKE;
private __gshared ubyte[32] NS_PEER_HOLEPUNCH;

shared static this() @trusted
{
    ubyte[32] ns;
    keyedBlake2b(ns[], cast(const(ubyte)[]) "hyperswarm/dht", []);
    ubyte[33] tmp;
    tmp[0 .. 32] = ns[];
    tmp[32] = 0;
    keyedBlake2b(NS_PEER_HANDSHAKE[], tmp[], []);
    tmp[32] = 1;
    keyedBlake2b(NS_PEER_HOLEPUNCH[], tmp[], []);
}

/// What a completed peer handshake yields (lib/noise-wrap.js final()).
struct HandshakeResult
{
    bool isInitiator;
    ubyte[32] publicKey;
    ubyte[32] remotePublicKey;
    ubyte[32] remoteId; // secret-stream id for the peer's role
    ubyte[32] holepunchSecret;
    ubyte[64] hash;
    ubyte[32] rx;
    ubyte[32] tx;
}

final class NoiseWrap
{
    private Noise hs;
    bool isInitiator;
    private Keypair keyPair;
    ubyte[32] remotePublicKey;

    /// `remotePublicKey` (32 bytes) makes this the initiator (IK knows the responder
    /// upfront); pass null/empty for the responder.
    this(Keypair keyPair, scope const(ubyte)[] remotePublicKey)
    {
        this.isInitiator = remotePublicKey.length == 32;
        this.keyPair = keyPair;
        this.hs = new Noise(Pattern.IK, isInitiator, keyPair);
        hs.initialise(NS_PEER_HANDSHAKE[], isInitiator ? remotePublicKey : null);
        if (isInitiator)
            this.remotePublicKey[] = remotePublicKey[0 .. 32];
    }

    /// Produce the next handshake message carrying `payload`.
    ubyte[] send(NoisePayload payload)
    {
        return hs.send(encodeNoisePayload(payload));
    }

    /// Consume a handshake message, returning the peer's noisePayload.
    NoisePayload recv(scope const(ubyte)[] buf)
    {
        auto payload = decodeNoisePayload(hs.recv(buf));
        remotePublicKey[] = hs.remoteStatic[];
        return payload;
    }

    bool complete() const @safe nothrow
    {
        return hs.complete;
    }

    /// The handshake result (throws if not complete).
    HandshakeResult finish()
    {
        if (!hs.complete)
            throw new Exception("noise-wrap: handshake unfinished");
        HandshakeResult r;
        r.isInitiator = isInitiator;
        r.publicKey = keyPair.publicKey;
        r.remotePublicKey[] = hs.remoteStatic[];
        r.hash[] = hs.handshakeHash[];
        r.rx[] = hs.rx[];
        r.tx[] = hs.tx[];
        r.remoteId = streamId(hs.handshakeHash[], !isInitiator);
        keyedBlake2b(r.holepunchSecret[], NS_PEER_HOLEPUNCH[], hs.handshakeHash[]);
        return r;
    }
}
