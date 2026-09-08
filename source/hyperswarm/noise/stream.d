/// hyperswarm's secret-stream, sans-io: the Noise XX handshake and the encrypted
/// transport, driven purely by bytes. The caller owns the socket — feed it bytes
/// received, get back bytes to send + decrypted messages; write plaintext, get back
/// framed bytes to send. Ported from @hyperswarm/secret-stream (pin b022ed6).
///
/// Wire (see notes/secret-stream-port.md): every frame is a uint24-LE length prefix
/// plus payload. Handshake messages are framed Noise messages. When the handshake
/// completes each side sends a setup frame = streamId(32) ++ secretstream header(24);
/// after both are exchanged, data frames carry secretstream ciphertext.
module hyperswarm.noise.stream;

import hyperswarm.noise.crypto : Keypair, keyedBlake2b;
import hyperswarm.noise.handshake : Noise, noiseXX;
import hyperswarm.noise.secretstream : Push, Pull, HEADERBYTES;

private enum size_t IDBYTES = 32;
private enum size_t IDHEADERBYTES = IDBYTES + HEADERBYTES; // 56

// The two namespace constants, derived exactly as hypercore-crypto's
// namespace('hyperswarm/secret-stream', 3) does: ns = BLAKE2b(name); NS[i] =
// BLAKE2b(ns ++ [i]). Role 0 = initiator, 1 = responder.
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

private ubyte[32] streamId(scope const(ubyte)[] handshakeHash, bool initiator) @trusted
{
    ubyte[32] id;
    keyedBlake2b(id[], initiator ? nsInitiator[] : nsResponder[], handshakeHash);
    return id;
}

/// Outputs of a feed(): bytes to write to the transport, decrypted messages, and
/// whether the stream became fully open (both setup frames exchanged) this call.
struct IoResult
{
    ubyte[] toSend;
    ubyte[][] messages;
    bool openedNow;
}

final class SecretStream
{
    private Noise hs;
    private bool isInitiator;
    private ubyte[] inbuf;

    private bool noiseComplete;
    private bool recvSetup;
    /// True once both sides have exchanged setup frames (data can flow both ways).
    bool opened;

    private Push enc;
    private Pull dec;
    private bool haveEnc;

    this(bool isInitiator, Keypair staticKp) @safe
    {
        this.isInitiator = isInitiator;
        this.hs = noiseXX(isInitiator, staticKp);
    }

    /// The peer's authenticated static public key (valid once opened).
    ubyte[32] remotePublicKey() const @safe nothrow
    {
        return hs.remoteStatic;
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

    /// Begin the handshake. Returns the initial bytes to send (the initiator's
    /// first message; nothing for the responder, which waits).
    ubyte[] start() @safe
    {
        hs.initialise();
        if (isInitiator)
            return frame(hs.send());
        return null;
    }

    private void setupEnc(ref IoResult res) @safe
    {
        enc = Push(hs.tx[]);
        dec = Pull(hs.rx[]);
        haveEnc = true;
        auto id = streamId(hs.handshakeHash[], isInitiator);
        ubyte[IDHEADERBYTES] idhdr;
        idhdr[0 .. IDBYTES] = id[];
        idhdr[IDBYTES .. $] = enc.header[];
        res.toSend ~= frame(idhdr[]);
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
                setupEnc(res);
            }
        }
        else if (!recvSetup)
        {
            if (f.length != IDHEADERBYTES)
                throw new Exception("secret-stream: bad setup frame length");
            auto expected = streamId(hs.handshakeHash[], !isInitiator);
            if (f[0 .. IDBYTES] != expected[])
                throw new Exception("secret-stream: peer id mismatch");
            dec.init(f[IDBYTES .. $]);
            recvSetup = true;
            opened = true;
            res.openedNow = true;
        }
        else
        {
            res.messages ~= dec.next(f);
        }
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

    /// Frame + encrypt an application message. Valid once the local handshake has
    /// completed (haveEnc); the peer can read it once it has our setup frame.
    ubyte[] write(scope const(ubyte)[] plaintext) @safe
    in (haveEnc, "secret-stream: write before handshake completed")
    {
        return frame(enc.next(plaintext));
    }
}
