/// Proves the Noise crypto primitives against byte-exact vectors generated from
/// the real JS (tests/noise_crypto_vectors.d). The handshake wire rides entirely
/// on these — HMAC-BLAKE2b, HKDF, ChaCha20-Poly1305 and the Ed25519 DH — so
/// "identical to the reference" is the only acceptable bar.
module tests.noise_crypto_test;

import fluent.asserts;
import hyperswarm.noise.crypto;
import tests.noise_crypto_vectors;
import std.format : format;

private string toHex(scope const(ubyte)[] b)
{
    string r;
    foreach (x; b)
        r ~= format("%02x", x);
    return r;
}

private string expect(string name)
{
    foreach (ref v; noiseCryptoVectors)
        if (v.name == name)
            return v.hex;
    assert(0, "missing vector: " ~ name);
}

private const(ubyte)[] b(string s)
{
    return cast(const(ubyte)[]) s;
}

@("noise crypto: HMAC-BLAKE2b matches the reference (incl. >BLOCKLEN key)")
unittest
{
    ubyte[64] o;
    hmacBlake2b(o, b("key"), [b("abc")]);
    toHex(o[]).should.equal(expect("hmac:short"));

    hmacBlake2b(o, b("salt"), [b("")]);
    toHex(o[]).should.equal(expect("hmac:empty-msg"));

    auto longKey = new ubyte[](200);
    longKey[] = 'k';
    hmacBlake2b(o, longKey, [b("message")]);
    toHex(o[]).should.equal(expect("hmac:longkey"));
}

@("noise crypto: HKDF (HMAC-BLAKE2b) matches the reference")
unittest
{
    toHex(hkdf(b("salt"), b("ikm"), 2)).should.equal(expect("hkdf:basic"));
    toHex(hkdf(b("chaining"), b(""), 2)).should.equal(expect("hkdf:empty-ikm"));
}

@("noise crypto: ChaCha20-Poly1305 IETF matches the reference (counter + AD)")
unittest
{
    ubyte[32] k1 = 1;
    toHex(chachaEncrypt(k1[], 0, [], b("hello"))).should.equal(expect("cipher:c0-noad"));

    ubyte[32] k2 = 2;
    ubyte[3] ad = [0xaa, 0xbb, 0xcc];
    toHex(chachaEncrypt(k2[], 5, ad[], b("payload data"))).should.equal(expect("cipher:c5-ad"));
}

@("noise crypto: ChaCha20-Poly1305 round-trips and rejects tampering")
unittest
{
    ubyte[32] k = 7;
    ubyte[3] ad = [1, 2, 3];
    auto ct = chachaEncrypt(k[], 3, ad[], b("round trip"));
    toHex(chachaDecrypt(k[], 3, ad[], ct)).should.equal(toHex(b("round trip")));

    ct[0] ^= 0xff; // tamper
    ({ cast(void) chachaDecrypt(k[], 3, ad[], ct); }).should.throwAnyException;
}

@("noise crypto: Ed25519 DH matches noise-curve-ed (fixed seeds)")
unittest
{
    ubyte[32] seedA = 3;
    ubyte[32] seedB = 9;
    auto kpA = ed25519Keypair(seedA[]);
    auto kpB = ed25519Keypair(seedB[]);

    toHex(kpA.publicKey[]).should.equal(expect("dh:pkA"));
    toHex(kpB.publicKey[]).should.equal(expect("dh:pkB"));

    ubyte[32] sharedSecret;
    ed25519DH(sharedSecret, kpB.publicKey[], kpA.secretKey[]);
    toHex(sharedSecret[]).should.equal(expect("dh:shared"));
}
