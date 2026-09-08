/// hyperdht's PEER_HOLEPUNCH wire byte-exact vs the reference (lib/messages.js):
/// the holepunch envelope and the holepunchPayload the two peers exchange during a
/// punch, plus round-trips through decode. Vectors generated from messages.js.
module tests.holepunch_messages_test;

import fluent.asserts;
import hyperswarm.dht.connect_messages;
import hyperswarm.cenc : Address;
import std.format : format;

private string toHex(scope const(ubyte)[] b)
{
    string r;
    foreach (x; b)
        r ~= format("%02x", x);
    return r;
}

@("hyperdht holepunch: envelope is byte-exact and round-trips")
unittest
{
    Holepunch h1;
    h1.mode = 2;
    h1.id = 7;
    h1.payload = [1, 2, 3, 4];
    toHex(encodeHolepunch(h1)).should.equal("0002070401020304");

    Holepunch h2;
    h2.mode = 0;
    h2.id = 65535;
    h2.payload = cast(ubyte[]) "hello".dup;
    h2.hasPeerAddress = true;
    h2.peerAddress = Address("1.2.3.4", 4, 4242);
    toHex(encodeHolepunch(h2)).should.equal("0100fdffff0568656c6c6f010203049210");

    auto d = decodeHolepunch(encodeHolepunch(h2));
    d.mode.should.equal(0);
    d.id.should.equal(65535);
    (cast(string) d.payload).should.equal("hello");
    d.hasPeerAddress.should.equal(true);
    d.peerAddress.host.should.equal("1.2.3.4");
    d.peerAddress.port.should.equal(4242);
}

@("hyperdht holepunch: payload is byte-exact and round-trips")
unittest
{
    HolepunchPayload p1;
    p1.error = 0;
    p1.firewall = 1;
    p1.round = 0;
    toHex(encodeHolepunchPayload(p1)).should.equal("00000100");

    ubyte[] tok = new ubyte[](32);
    foreach (i; 0 .. 32)
        tok[i] = cast(ubyte) i;
    ubyte[] rtok = new ubyte[](32);
    rtok[] = 0xab;

    HolepunchPayload p2;
    p2.error = 3;
    p2.firewall = 2;
    p2.round = 5;
    p2.connected = true;
    p2.punching = true;
    p2.addresses = [Address("10.0.0.1", 4, 1), Address("192.168.1.9", 4, 9999)];
    p2.hasRemoteAddress = true;
    p2.remoteAddress = Address("8.8.8.8", 4, 53);
    p2.token = tok;
    p2.remoteToken = rtok;
    toHex(encodeHolepunchPayload(p2)).should.equal(
        "3f030205020a0000010100c0a801090f27080808083500000102030405060708090a0b0c0d0e0f"
        ~ "101112131415161718191a1b1c1d1e1fabababababababababababababababababababababababababababababababab");

    auto d = decodeHolepunchPayload(encodeHolepunchPayload(p2));
    d.error.should.equal(3);
    d.firewall.should.equal(2);
    d.round.should.equal(5);
    d.connected.should.equal(true);
    d.punching.should.equal(true);
    d.addresses.length.should.equal(2);
    d.addresses[1].port.should.equal(9999);
    d.hasRemoteAddress.should.equal(true);
    d.remoteAddress.host.should.equal("8.8.8.8");
    toHex(d.token).should.equal(toHex(tok));
    toHex(d.remoteToken).should.equal(toHex(rtok));
}
