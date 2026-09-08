/// The Kademlia routing table: bucketing, closest(), get/remove/size, and the
/// XOR-distance comparison the iterative query relies on.
module tests.dht_table_test;

import fluent.asserts;
import hyperswarm.dht.table;

private Node mk(ubyte first, ushort port)
{
    Node n;
    n.id[0] = first;
    n.host = "127.0.0.1";
    n.port = port;
    return n;
}

@("dht table: add/get/remove/size and closest")
unittest
{
    ubyte[32] zero;
    auto t = new RoutingTable(zero, 20);

    t.add(mk(0x01, 1));
    t.add(mk(0x02, 2));
    t.add(mk(0x80, 3));
    t.add(mk(0xff, 4));
    t.size.should.equal(4);

    ubyte[32] want2;
    want2[0] = 0x02;
    auto g = t.get(want2[]);
    (g !is null).should.equal(true);
    g.port.should.equal(2);

    ubyte[32] target;
    auto c = t.closest(target[], 20);
    c.length.should.equal(4);

    t.remove(want2[]).should.equal(true);
    t.size.should.equal(3);
    (t.get(want2[]) is null).should.equal(true);
}

@("dht table: closest is capped at k")
unittest
{
    ubyte[32] zero;
    auto t = new RoutingTable(zero, 4);
    foreach (i; 1 .. 20)
        t.add(mk(cast(ubyte) i, cast(ushort) i));
    ubyte[32] target;
    // buckets each hold up to k; closest returns at most `want`
    t.closest(target[], 4).length.should.equal(4);
}

@("dht table: XOR distance comparison")
unittest
{
    ubyte[32] a, b, target;
    a[0] = 0x01;
    b[0] = 0x02;
    // to target 0, 0x01 is closer than 0x02
    compareDistance(a[], b[], target[]).should.equal(-1);
    compareDistance(b[], a[], target[]).should.equal(1);
    compareDistance(a[], a[], target[]).should.equal(0);

    // flip the target: nearer to 0x02 now
    target[0] = 0x02;
    compareDistance(b[], a[], target[]).should.equal(-1);
}
