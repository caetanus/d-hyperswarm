/// Proves the Noise XX handshake byte-for-byte against noise-handshake (Ed25519),
/// with fixed static (seeds 1/2) and ephemeral (seeds 11/12) keys — vectors in
/// tests/noise_hs_vectors.d. Checks the three message bytes, the payloads, the
/// derived transport keys and handshake hash (agreed by both sides), and the
/// authenticated remote static keys.
module tests.noise_hs_test;

import fluent.asserts;
import hyperswarm.noise.handshake : NoiseXX;
import hyperswarm.noise.crypto : ed25519Keypair, Keypair;
import tests.noise_hs_vectors;
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
    foreach (ref v; noiseHsVectors)
        if (v.name == name)
            return v.hex;
    assert(0, "missing vector: " ~ name);
}

private const(ubyte)[] b(string s)
{
    return cast(const(ubyte)[]) s;
}

private Keypair seedKp(ubyte val)
{
    ubyte[32] s = val;
    return ed25519Keypair(s[]);
}

@("noise XX: the three-message handshake is byte-exact and both sides agree")
unittest
{
    auto eI = seedKp(11);
    auto eR = seedKp(12);
    auto init = new NoiseXX(true, seedKp(1), &eI);
    auto resp = new NoiseXX(false, seedKp(2), &eR);
    init.initialise();
    resp.initialise();

    auto m1 = init.send(b("msg1payload"));
    toHex(m1).should.equal(expect("xx:msg1"));
    toHex(resp.recv(m1)).should.equal(toHex(b("msg1payload")));

    auto m2 = resp.send(b("msg2payload"));
    toHex(m2).should.equal(expect("xx:msg2"));
    toHex(init.recv(m2)).should.equal(toHex(b("msg2payload")));

    auto m3 = init.send(b("msg3payload"));
    toHex(m3).should.equal(expect("xx:msg3"));
    toHex(resp.recv(m3)).should.equal(toHex(b("msg3payload")));

    init.complete.should.equal(true);
    resp.complete.should.equal(true);

    // transport keys + handshake hash match the reference (initiator's view)
    toHex(init.tx[]).should.equal(expect("xx:init-tx"));
    toHex(init.rx[]).should.equal(expect("xx:init-rx"));
    toHex(init.handshakeHash[]).should.equal(expect("xx:hash"));

    // the two sides derive the mirror-image keys and the same hash
    toHex(resp.rx[]).should.equal(toHex(init.tx[]));
    toHex(resp.tx[]).should.equal(toHex(init.rx[]));
    toHex(resp.handshakeHash[]).should.equal(toHex(init.handshakeHash[]));

    // each learned the other's authenticated static key
    toHex(init.remoteStatic[]).should.equal(expect("xx:rs-init"));
    toHex(resp.remoteStatic[]).should.equal(expect("xx:rs-resp"));
}

@("noise XX: a full handshake with random ephemerals still agrees on keys")
unittest
{
    // no fixed ephemerals — exercises the random-keypair path both sides use live
    auto init = new NoiseXX(true, seedKp(5));
    auto resp = new NoiseXX(false, seedKp(6));
    init.initialise();
    resp.initialise();

    resp.recv(init.send());
    init.recv(resp.send());
    resp.recv(init.send());

    init.complete.should.equal(true);
    toHex(init.tx[]).should.equal(toHex(resp.rx[]));
    toHex(init.rx[]).should.equal(toHex(resp.tx[]));
    toHex(init.handshakeHash[]).should.equal(toHex(resp.handshakeHash[]));
}
