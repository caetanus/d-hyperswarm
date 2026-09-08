/// Drives two SecretStreams against each other in memory: the full Noise XX
/// handshake, the setup-frame exchange, then an encrypted message echoed back.
/// Sanity for the sans-io state machine before the D⇄JS interop proves the wire.
module tests.secretstream_test;

import fluent.asserts;
import hyperswarm.noise.stream : SecretStream;
import hyperswarm.noise.crypto : ed25519Keypair, Keypair;

private Keypair kp(ubyte v)
{
    ubyte[32] s = v;
    return ed25519Keypair(s[]);
}

@("secret-stream: D<->D handshake, setup, and an encrypted echo")
unittest
{
    auto a = new SecretStream(true, kp(1)); // initiator
    auto b = new SecretStream(false, kp(2)); // responder

    ubyte[][] aMsgs, bMsgs;
    ubyte[] forA, forB;
    bool sent;

    b.start(); // responder: initialises Noise, sends nothing yet
    forB = a.start();
    foreach (_; 0 .. 24)
    {
        if (forB.length)
        {
            auto r = b.feed(forB);
            forB = null;
            forA ~= r.toSend;
            foreach (m; r.messages)
            {
                bMsgs ~= m;
                forA ~= b.write(m); // echo it back
            }
        }
        if (forA.length)
        {
            auto r = a.feed(forA);
            forA = null;
            forB ~= r.toSend;
            foreach (m; r.messages)
                aMsgs ~= m;
        }
        if (a.opened && b.opened && !sent)
        {
            forB ~= a.write(cast(const(ubyte)[]) "hello secret");
            sent = true;
        }
    }

    a.opened.should.equal(true);
    b.opened.should.equal(true);

    // the message A sent reached B, and B's echo reached A
    (bMsgs.length >= 1).should.equal(true);
    (aMsgs.length >= 1).should.equal(true);
    (cast(string) bMsgs[0]).should.equal("hello secret");
    (cast(string) aMsgs[0]).should.equal("hello secret");

    // each authenticated the other's static identity
    a.remotePublicKey.should.equal(kp(2).publicKey);
    b.remotePublicKey.should.equal(kp(1).publicKey);
}
