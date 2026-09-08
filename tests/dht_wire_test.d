/// Proves the dht-rpc packet wire against byte-exact vectors built with the same
/// compact-encoding logic as dht-rpc's lib/io.js (tests/dht_vectors.d), and
/// round-trips a request through decode. Reply decoding is exercised live against
/// a real dht-rpc node in the interop.
module tests.dht_wire_test;

import fluent.asserts;
import hyperswarm.dht.wire;
import hyperswarm.cenc : Address;
import tests.dht_vectors;
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
    foreach (ref v; dhtVectors)
        if (v.name == name)
            return v.hex;
    assert(0, "missing vector: " ~ name);
}

@("dht wire: request encoding + node id are byte-exact vs dht-rpc")
unittest
{
    ubyte[32] target = 7;
    auto fn = encodeRequest(0xABCD, Address("1.2.3.4", 4, 49737), FIND_NODE, target[]);
    toHex(fn).should.equal(expect("req:findnode"));

    auto pg = encodeRequest(0x0102, Address("1.2.3.4", 4, 49737), PING);
    toHex(pg).should.equal(expect("req:ping"));

    toHex(nodeId("1.2.3.4", 49737)[]).should.equal(expect("nodeid"));
}

@("dht wire: a request round-trips through decode")
unittest
{
    ubyte[32] target = 9;
    auto buf = encodeRequest(0xBEEF, Address("5.6.7.8", 4, 1234), FIND_NODE, target[]);
    auto req = decodeRequest(buf);
    req.tid.should.equal(0xBEEF);
    req.command.should.equal(FIND_NODE);
    req.internal.should.equal(true);
    req.to.host.should.equal("5.6.7.8");
    req.to.port.should.equal(1234);
    req.target.should.equal(target[]);

    auto ping = decodeRequest(encodeRequest(1, Address("9.9.9.9", 4, 53), PING));
    ping.command.should.equal(PING);
    ping.target.length.should.equal(0);
}
