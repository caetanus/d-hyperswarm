/// hyperswarm's secret-stream, sans-io: driven purely by bytes. The caller owns the
/// socket — feed it bytes received (get back bytes to send + decrypted messages),
/// write plaintext (get back framed bytes). Ported from @hyperswarm/secret-stream
/// (pin b022ed6).
///
/// Two modes: a standalone stream does the Noise XX handshake itself; a connection
/// established by hyperdht instead starts from the IK handshake's tx/rx/hash
/// (fromHandshake) and only does the secret-stream setup-frame exchange.
///
/// Wire: every frame is a uint24-LE length prefix + payload. Handshake messages are
/// framed Noise messages. On completion each side sends a setup frame = streamId(32)
/// ++ secretstream header(24); after both are exchanged, data frames carry
/// secretstream ciphertext.
module hyperswarm.noise.stream;

import hyperswarm.noise.crypto : Keypair, keyedBlake2b;
import hyperswarm.noise.handshake : Noise, noiseXX;
import hyperswarm.noise.secretstream : Push, Pull, HEADERBYTES;

private enum size_t IDBYTES = 32;
private enum size_t IDHEADERBYTES = IDBYTES + HEADERBYTES; // 56

private __gshared ubyte[32] nsInitiator;
private __gshared ubyte[32] nsResponder;

shared static this() @trusted
{
    ubyte[32] ns;
    keyedBlake2b(ns[], cast(const(ubyte)[]) "hyperswarm/secret-stream", []);
    ubyte[33] tmp;
    tmp[0 .. 32] = ns[];
    tmp[32] = 0;
    keyedBlake2b(nsInitiator[], tmp[], []);
    tmp[32] = 1;
    keyedBlake2b(nsResponder[], tmp[], []);
}

/// secret-stream's per-role stream id: keyed-BLAKE2b(NS_role, key=handshakeHash).
/// (Also hyperdht's noise-wrap remoteId.)
ubyte[32] streamId(scope const(ubyte)[] handshakeHash, bool initiator) @trusted
{
    ubyte[32] id;
    keyedBlake2b(id[], initiator ? nsInitiator[] : nsResponder[], handshakeHash);
    return id;
}

struct IoResult
{
    ubyte[] toSend;
    ubyte[][] messages;
    bool openedNow;
}

final class SecretStream
{
    private Noise hs; // null in fromHandshake mode
    private bool isInitiator;
    private ubyte[] inbuf;

    private bool noiseComplete;
    private bool recvSetup;
    bool opened;

    private Push enc;
    private Pull dec;
    private bool haveEnc;

    private ubyte[32] txKey;
    private ubyte[32] rxKey;
    private ubyte[64] hsHash;
    private ubyte[32] remotePub;

    this(bool isInitiator, Keypair staticKp) @safe
    {
        this.isInitiator = isInitiator;
        this.hs = noiseXX(isInitiator, staticKp);
    }

    private this(bool isInitiator, ubyte[32] tx, ubyte[32] rx, ubyte[64] hash, ubyte[32] remotePublicKey) @safe
    {
        this.isInitiator = isInitiator;
        this.txKey = tx;
        this.rxKey = rx;
        this.hsHash = hash;
        this.remotePub = remotePublicKey;
        this.noiseComplete = true;
    }

    /// Build a connection secret-stream from a completed (IK) handshake — skip the
    /// Noise handshake and only run the secret-stream transport over the socket.
    static SecretStream fromHandshake(bool isInitiator, ubyte[32] tx, ubyte[32] rx,
        ubyte[64] hash, ubyte[32] remotePublicKey) @safe
    {
        return new SecretStream(isInitiator, tx, rx, hash, remotePublicKey);
    }

    /// The peer's authenticated static public key.
    ubyte[32] remotePublicKey() const @safe nothrow
    {
        return hs is null ? remotePub : hs.remoteStatic;
    }

    private static ubyte[] frame(scope const(ubyte)[] payload) @safe
    {
        auto f = new ubyte[](3 + payload.length);
        immutable len = payload.length;
        f[0] = cast(ubyte) len;
        f[1] = cast(ubyte)(len >> 8);
        f[2] = cast(ubyte)(len >> 16);
        f[3 .. $] = payload[];
        return f;
    }

    private ubyte[] setupFrame() @safe
    {
        enc = Push(txKey[]);
        dec = Pull(rxKey[]);
        haveEnc = true;
        auto id = streamId(hsHash[], isInitiator);
        ubyte[IDHEADERBYTES] idhdr;
        idhdr[0 .. IDBYTES] = id[];
        idhdr[IDBYTES .. $] = enc.header[];
        return frame(idhdr[]);
    }

    /// Begin. Returns the initial bytes to send (the initiator's first handshake
    /// message for a standalone stream; the setup frame for a fromHandshake one).
    ubyte[] start() @safe
    {
        if (hs is null)
            return setupFrame(); // connection: keys already known, send setup
        hs.initialise();
        if (isInitiator)
            return frame(hs.send());
        return null;
    }

    private void onNoiseComplete(ref IoResult res) @safe
    {
        txKey[] = hs.tx[];
        rxKey[] = hs.rx[];
        hsHash[] = hs.handshakeHash[];
        res.toSend ~= setupFrame();
    }

    private void process(scope const(ubyte)[] f, ref IoResult res) @safe
    {
        if (!noiseComplete)
        {
            hs.recv(f);
            if (!hs.complete)
                res.toSend ~= frame(hs.send());
            if (hs.complete)
            {
                noiseComplete = true;
                onNoiseComplete(res);
            }
        }
        else if (!recvSetup)
        {
            if (f.length != IDHEADERBYTES)
                throw new Exception("secret-stream: bad setup frame length");
            auto expected = streamId(hsHash[], !isInitiator);
            if (f[0 .. IDBYTES] != expected[])
                throw new Exception("secret-stream: peer id mismatch");
            dec.init(f[IDBYTES .. $]);
            recvSetup = true;
            opened = true;
            res.openedNow = true;
        }
        else
            res.messages ~= dec.next(f);
    }

    /// Feed bytes received from the transport; drives the handshake and decrypts.
    IoResult feed(scope const(ubyte)[] bytes) @safe
    {
        inbuf ~= bytes;
        IoResult res;
        while (inbuf.length >= 3)
        {
            immutable size_t len = inbuf[0] | (cast(size_t) inbuf[1] << 8) | (cast(size_t) inbuf[2] << 16);
            if (inbuf.length < 3 + len)
                break;
            auto f = inbuf[3 .. 3 + len].dup;
            inbuf = inbuf[3 + len .. $].dup;
            process(f, res);
        }
        return res;
    }

    /// Frame + encrypt an application message (valid once the local side is set up).
    ubyte[] write(scope const(ubyte)[] plaintext) @safe
    in (haveEnc, "secret-stream: write before setup")
    {
        return frame(enc.next(plaintext));
    }
}
