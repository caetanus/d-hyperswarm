/// The hyperdht peer handshake (Noise IK) + building a connection secret-stream
/// from its result. Both sides exchange noisePayloads, agree on tx/rx/hash and the
/// holepunch secret, learn each other's static key — then a SecretStream built from
/// those keys (skipping the XX handshake) echoes an encrypted message.
module tests.noise_wrap_test;

import fluent.asserts;
import hyperswarm.dht.noise_wrap : NoiseWrap, HandshakeResult;
import hyperswarm.dht.connect_messages : NoisePayload, UdxInfo, FW_OPEN;
import hyperswarm.noise.crypto : ed25519RandomKeypair, Keypair;
import hyperswarm.noise.stream : SecretStream;
import std.format : format;

private string toHex(scope const(ubyte)[] b)
{
    string r;
    foreach (x; b)
        r ~= format("%02x", x);
    return r;
}

// Run a full IK peer handshake, returning both results.
private void peerHandshake(out HandshakeResult ri, out HandshakeResult rr,
    out Keypair client, out Keypair server)
{
    server = ed25519RandomKeypair();
    client = ed25519RandomKeypair();
    auto init = new NoiseWrap(client, server.publicKey[]); // initiator knows server key
    auto resp = new NoiseWrap(server, null);

    NoisePayload p1;
    p1.firewall = FW_OPEN;
    p1.hasUdx = true;
    p1.udx = UdxInfo(1, false, 101, 0);
    p1.hasSecretStream = true;
    auto rp1 = resp.recv(init.send(p1));
    assert(rp1.udx.id == 101);

    NoisePayload p2;
    p2.firewall = FW_OPEN;
    p2.hasUdx = true;
    p2.udx = UdxInfo(1, false, 202, 0);
    p2.hasSecretStream = true;
    auto rp2 = init.recv(resp.send(p2));
    assert(rp2.udx.id == 202);

    ri = init.finish();
    rr = resp.finish();
}

@("noise-wrap: IK peer handshake agrees on keys, secret, and identities")
unittest
{
    HandshakeResult ri, rr;
    Keypair client, server;
    peerHandshake(ri, rr, client, server);

    toHex(ri.tx[]).should.equal(toHex(rr.rx[]));
    toHex(ri.rx[]).should.equal(toHex(rr.tx[]));
    toHex(ri.hash[]).should.equal(toHex(rr.hash[]));
    toHex(ri.holepunchSecret[]).should.equal(toHex(rr.holepunchSecret[]));
    toHex(ri.remotePublicKey[]).should.equal(toHex(server.publicKey[]));
    toHex(rr.remotePublicKey[]).should.equal(toHex(client.publicKey[]));
    // each side's remoteId is the other's own stream id
    toHex(ri.remoteId[]).should.not.equal(toHex(rr.remoteId[]));
}

@("secret-stream fromHandshake: a connection built from IK keys echoes")
unittest
{
    HandshakeResult ri, rr;
    Keypair client, server;
    peerHandshake(ri, rr, client, server);

    auto a = SecretStream.fromHandshake(true, ri.tx, ri.rx, ri.hash, ri.remotePublicKey);
    auto b = SecretStream.fromHandshake(false, rr.tx, rr.rx, rr.hash, rr.remotePublicKey);

    ubyte[][] aMsgs, bMsgs;
    ubyte[] forB = a.start();
    ubyte[] forA = b.start();
    bool sent;

    foreach (_; 0 .. 16)
    {
        if (forB.length)
        {
            auto r = b.feed(forB);
            forB = null;
            forA ~= r.toSend;
            foreach (m; r.messages)
            {
                bMsgs ~= m;
                forA ~= b.write(m); // echo
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
            forB ~= a.write(cast(const(ubyte)[]) "conn hello");
            sent = true;
        }
    }

    a.opened.should.equal(true);
    b.opened.should.equal(true);
    (bMsgs.length >= 1).should.equal(true);
    (cast(string) bMsgs[0]).should.equal("conn hello");
    (cast(string) aMsgs[0]).should.equal("conn hello");
}
