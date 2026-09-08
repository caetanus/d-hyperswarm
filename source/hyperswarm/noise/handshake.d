/// The Noise handshake (SymmetricState + the pattern walk) on the Ed25519 curve,
/// ported from noise-handshake (pin dc1f9c4). Supports the two patterns hyperswarm
/// uses: XX (secret-stream's mutual handshake) and IK (hyperdht's peer handshake,
/// where the initiator already knows the responder's static key). Protocol name
/// Noise_<PATTERN>_Ed25519_ChaChaPoly_BLAKE2b. The wire is asserted byte-for-byte
/// against the reference (fixed keys) in the tests.
///
///   XX: 1. → [e]   2. ← [e,ee,s,es]   3. → [s,se]
///   IK: (rs preshared)  1. → [e,es,s,ss]   2. ← [e,ee,se]
module hyperswarm.noise.handshake;

import hyperswarm.noise.crypto;

enum Pattern
{
    XX,
    IK
}

private enum Tok
{
    E,
    S,
    EE,
    ES,
    SE,
    SS
}

private static immutable Tok[][] XX_MSGS = [
    [Tok.E],
    [Tok.E, Tok.EE, Tok.S, Tok.ES],
    [Tok.S, Tok.SE]
];

private static immutable Tok[][] IK_MSGS = [
    [Tok.E, Tok.ES, Tok.S, Tok.SS],
    [Tok.E, Tok.EE, Tok.SE]
];

/// A Noise handshake role. Not thread-safe; one per connection.
final class Noise
{
    private ubyte[HASHLEN] digest;
    private ubyte[HASHLEN] chainingKey;

    private ubyte[32] cipherKey;
    private bool hasKey;
    private uint nonce;

    private Pattern pattern;
    private Keypair s; // our static
    private Keypair e; // our ephemeral
    private bool haveE;
    private ubyte[PKLEN] rs; // remote static
    private bool haveRs;
    private ubyte[PKLEN] re; // remote ephemeral

    private bool initiator;
    private size_t step;

    ubyte[32] tx;
    ubyte[32] rx;
    ubyte[HASHLEN] handshakeHash;
    bool complete;

    /// The peer's authenticated static public key.
    ubyte[PKLEN] remoteStatic() const @safe nothrow
    {
        return rs;
    }

    /// `staticKp` is our identity. `ephemeral`, when given, fixes the ephemeral key
    /// (tests); otherwise it is generated on first use.
    this(Pattern pattern, bool initiator, Keypair staticKp, Keypair* ephemeral = null) @safe
    {
        this.pattern = pattern;
        this.initiator = initiator;
        this.s = staticKp;
        if (ephemeral !is null)
        {
            this.e = *ephemeral;
            this.haveE = true;
        }
    }

    private const(Tok[][]) msgs() const @safe
    {
        return pattern == Pattern.XX ? XX_MSGS : IK_MSGS;
    }

    private string protocolName() const @safe
    {
        return pattern == Pattern.XX
            ? "Noise_XX_Ed25519_ChaChaPoly_BLAKE2b" : "Noise_IK_Ed25519_ChaChaPoly_BLAKE2b";
    }

    /// Mix in the protocol name, prologue, and (for IK) the pre-shared responder
    /// static. `remoteStatic` is required for an IK initiator.
    void initialise(scope const(ubyte)[] prologue = null, scope const(ubyte)[] remoteStatic = null) @trusted
    {
        immutable proto = protocolName();
        digest[] = 0;
        assert(proto.length <= HASHLEN);
        digest[0 .. proto.length] = cast(const(ubyte)[]) proto;
        chainingKey[] = digest[];
        mixHash(prologue);

        if (pattern == Pattern.IK)
        {
            // preshare RS: the initiator mixes the (known) remote static, the
            // responder mixes its own static.
            if (initiator)
            {
                assert(remoteStatic.length == PKLEN, "IK initiator needs the remote static key");
                rs[] = remoteStatic[0 .. PKLEN];
                haveRs = true;
                mixHash(rs[]);
            }
            else
                mixHash(s.publicKey[]);
        }
    }

    private void mixHash(scope const(ubyte)[] data) @trusted
    {
        auto tmp = new ubyte[](HASHLEN + data.length);
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
        foreach (t; msgs[step])
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
        if (step == msgs.length)
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

        foreach (t; msgs[step])
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
                haveRs = true;
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
        if (step == msgs.length)
            split();
        return payload;
    }
}

/// XX convenience (secret-stream): a mutual handshake with no pre-shared key.
Noise noiseXX(bool initiator, Keypair staticKp, Keypair* ephemeral = null) @safe
{
    return new Noise(Pattern.XX, initiator, staticKp, ephemeral);
}
