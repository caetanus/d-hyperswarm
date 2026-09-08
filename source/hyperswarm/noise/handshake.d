/// The Noise XX handshake (SymmetricState + the three XX messages), ported from
/// noise-handshake (pin dc1f9c4) on the Ed25519 curve. Protocol:
/// Noise_XX_Ed25519_ChaChaPoly_BLAKE2b. This drives secret-stream's mutual
/// authentication; the wire is asserted byte-for-byte against the reference (with
/// fixed static + ephemeral keys) in the tests.
///
/// XX message pattern:
///   1. →  [e]            2. ←  [e, ee, s, es]            3. →  [s, se]
/// followed on each message by an encrypted payload. After message 3 both sides
/// split the chaining key into tx/rx transport keys.
module hyperswarm.noise.handshake;

import hyperswarm.noise.crypto;

private enum Tok
{
    E,
    S,
    EE,
    ES,
    SE,
    SS
}

// The XX pattern: one token list per message.
private static immutable Tok[][3] XX = [
    [Tok.E],
    [Tok.E, Tok.EE, Tok.S, Tok.ES],
    [Tok.S, Tok.SE]
];

/// A Noise XX handshake role (initiator or responder). Fold of SymmetricState +
/// the pattern walk. Not thread-safe; one per connection.
final class NoiseXX
{
    private ubyte[HASHLEN] digest;
    private ubyte[HASHLEN] chainingKey;

    private ubyte[32] cipherKey;
    private bool hasKey;
    private uint nonce;

    private Keypair s; // our static
    private Keypair e; // our ephemeral
    private bool haveE;
    private ubyte[PKLEN] rs; // remote static
    private ubyte[PKLEN] re; // remote ephemeral

    private bool initiator;
    private size_t step;

    /// Transport keys, valid once `complete`.
    ubyte[32] tx;
    ubyte[32] rx;
    ubyte[HASHLEN] handshakeHash;
    bool complete;

    /// The peer's authenticated static public key (valid once the S token of the
    /// handshake has been received). secret-stream uses this as the peer identity.
    ubyte[PKLEN] remoteStatic() const @safe nothrow
    {
        return rs;
    }

    /// `staticKp` is our long-term identity. `ephemeral`, when given, fixes the
    /// ephemeral key (tests); otherwise it is generated on first use.
    this(bool initiator, Keypair staticKp, Keypair* ephemeral = null) @safe
    {
        this.initiator = initiator;
        this.s = staticKp;
        if (ephemeral !is null)
        {
            this.e = *ephemeral;
            this.haveE = true;
        }
    }

    private enum PROTOCOL = "Noise_XX_Ed25519_ChaChaPoly_BLAKE2b";

    /// Mix in the protocol name and prologue. Must be called before send/recv.
    void initialise(scope const(ubyte)[] prologue = null) @trusted
    {
        static assert(PROTOCOL.length <= HASHLEN);
        digest[] = 0;
        digest[0 .. PROTOCOL.length] = cast(const(ubyte)[]) PROTOCOL;
        chainingKey[] = digest[];
        mixHash(prologue);
    }

    private void mixHash(scope const(ubyte)[] data) @trusted
    {
        ubyte[] tmp = new ubyte[](HASHLEN + data.length);
        tmp[0 .. HASHLEN] = digest[];
        tmp[HASHLEN .. $] = data[];
        blake2b(digest, tmp);
    }

    private void initKey(scope const(ubyte)[] k) @safe
    {
        cipherKey[] = k[0 .. 32];
        hasKey = true;
        nonce = 0;
    }

    private void mixKey(scope const(ubyte)[] remotePub, ref Keypair localKp) @trusted
    {
        ubyte[DHLEN] dh;
        ed25519DH(dh, remotePub, localKp.secretKey[]);
        auto res = hkdf(chainingKey[], dh[], 2);
        chainingKey[] = res[0 .. HASHLEN];
        initKey(res[HASHLEN .. HASHLEN + 32]);
    }

    private ubyte[] encryptAndHash(scope const(ubyte)[] pt) @trusted
    {
        ubyte[] ct;
        if (hasKey)
        {
            ct = chachaEncrypt(cipherKey[], nonce, digest[], pt);
            nonce++;
        }
        else
            ct = pt.dup;
        mixHash(ct);
        return ct;
    }

    private ubyte[] decryptAndHash(scope const(ubyte)[] ct) @trusted
    {
        ubyte[] pt;
        if (hasKey)
        {
            pt = chachaDecrypt(cipherKey[], nonce, digest[], ct);
            nonce++;
        }
        else
            pt = ct.dup;
        mixHash(ct);
        return pt;
    }

    private void split() @trusted
    {
        auto res = hkdf(chainingKey[], [], 2);
        auto k1 = res[0 .. 32];
        auto k2 = res[HASHLEN .. HASHLEN + 32];
        tx[] = initiator ? k1 : k2;
        rx[] = initiator ? k2 : k1;
        handshakeHash[] = digest[];
        complete = true;
    }

    // local key for a DH token: static (s) or ephemeral (e)
    private void mixKeyToken(Tok t) @trusted
    {
        bool useLocalStatic, useRemoteStatic;
        final switch (t)
        {
        case Tok.EE:
            break;
        case Tok.ES:
            useLocalStatic = !initiator;
            useRemoteStatic = initiator;
            break;
        case Tok.SE:
            useLocalStatic = initiator;
            useRemoteStatic = !initiator;
            break;
        case Tok.SS:
            useLocalStatic = true;
            useRemoteStatic = true;
            break;
        case Tok.E:
        case Tok.S:
            assert(0);
        }
        const(ubyte)[] remotePub = useRemoteStatic ? rs[] : re[];
        mixKey(remotePub, useLocalStatic ? s : e);
    }

    /// Produce the next handshake message carrying `payload`.
    ubyte[] send(scope const(ubyte)[] payload = null) @trusted
    {
        ubyte[] outp;
        foreach (t; XX[step])
        {
            final switch (t)
            {
            case Tok.E:
                if (!haveE)
                {
                    e = ed25519RandomKeypair();
                    haveE = true;
                }
                mixHash(e.publicKey[]);
                outp ~= e.publicKey[];
                break;
            case Tok.S:
                outp ~= encryptAndHash(s.publicKey[]);
                break;
            case Tok.EE:
            case Tok.ES:
            case Tok.SE:
            case Tok.SS:
                mixKeyToken(t);
                break;
            }
        }
        outp ~= encryptAndHash(payload);
        step++;
        if (step == XX.length)
            split();
        return outp;
    }

    /// Consume a handshake message, returning its payload.
    ubyte[] recv(scope const(ubyte)[] buf) @trusted
    {
        size_t off = 0;
        const(ubyte)[] shift(size_t n)
        {
            if (off + n > buf.length)
                throw new Exception("Insufficient bytes");
            auto r = buf[off .. off + n];
            off += n;
            return r;
        }

        foreach (t; XX[step])
        {
            final switch (t)
            {
            case Tok.E:
                re[] = shift(PKLEN);
                mixHash(re[]);
                break;
            case Tok.S:
                immutable klen = hasKey ? PKLEN + MACBYTES : PKLEN;
                rs[] = decryptAndHash(shift(klen));
                break;
            case Tok.EE:
            case Tok.ES:
            case Tok.SE:
            case Tok.SS:
                mixKeyToken(t);
                break;
            }
        }
        auto payload = decryptAndHash(buf[off .. $]);
        step++;
        if (step == XX.length)
            split();
        return payload;
    }
}
