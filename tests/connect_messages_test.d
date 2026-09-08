/// hyperdht's peer-handshake wire byte-exact vs the reference (tests/connect_vectors.d):
/// the handshake envelope and the noisePayload (addresses + udx + secretStream), plus
/// round-trips through decode.
module tests.connect_messages_test;

import fluent.asserts;
import hyperswarm.dht.connect_messages;
import hyperswarm.cenc : Address;
import tests.connect_vectors;
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
    foreach (ref v; connectVectors)
        if (v.name == name)
            return v.hex;
    assert(0, "missing vector: " ~ name);
}

@("hyperdht connect: handshake + noisePayload are byte-exact and round-trip")
unittest
{
    ubyte[] noise = [1, 2, 3];
    Handshake hs;
    hs.mode = 0;
    hs.noise = noise;
    hs.hasPeerAddress = true;
    hs.peerAddress = Address("1.2.3.4", 4, 5);
    toHex(encodeHandshake(hs)).should.equal(expect("handshake_enc"));

    auto dh = decodeHandshake(encodeHandshake(hs));
    dh.mode.should.equal(0);
    dh.noise.length.should.equal(3);
    dh.peerAddress.host.should.equal("1.2.3.4");
    dh.peerAddress.port.should.equal(5);

    NoisePayload np;
    np.error = 0;
    np.firewall = FW_OPEN;
    np.addresses4 = [Address("1.2.3.4", 4, 5)];
    np.hasUdx = true;
    np.udx = UdxInfo(1, false, 7, 0);
    np.hasSecretStream = true;
    toHex(encodeNoisePayload(np)).should.equal(expect("noisepayload_enc"));

    auto dn = decodeNoisePayload(encodeNoisePayload(np));
    dn.ver.should.equal(1);
    dn.firewall.should.equal(FW_OPEN);
    dn.addresses4.length.should.equal(1);
    dn.addresses4[0].port.should.equal(5);
    dn.hasUdx.should.equal(true);
    dn.udx.id.should.equal(7);
    dn.hasSecretStream.should.equal(true);
}
