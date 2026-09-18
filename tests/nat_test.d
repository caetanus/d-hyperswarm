/// Holepunch Stage C: the NAT sampler classifier (nat.js port). Synthetic {to,
/// from} sequences drive every branch of _updateFirewall / _updateAddresses, so
/// the interop-fragile thresholds are pinned without needing the live network.
module tests.nat_test;

import fluent.asserts;
import hyperswarm.dht.nat : Nat;
import hyperswarm.cenc : Address;
import hyperswarm.dht.connect_messages : FW_OPEN, FW_CONSISTENT, FW_RANDOM;

private Address to(string host, ushort port)
{
    return Address(host, 4, port);
}

private Address peer(ubyte n)
{
    import std.format : format;

    return Address(format("9.9.9.%d", n), 4, 4242);
}

@("nat: not firewalled classifies OPEN immediately")
unittest
{
    auto n = new Nat(false); // not firewalled
    n.add(to("1.2.3.4", 100), peer(1));
    n.firewall.should.equal(FW_OPEN);
}

@("nat: the same external host+port to every responder is CONSISTENT (max>=3)")
unittest
{
    auto n = new Nat(true);
    foreach (i; 0 .. 3)
        n.add(to("5.5.5.5", 100), peer(cast(ubyte) i)); // identical mapping, 3 peers
    n.firewall.should.equal(FW_CONSISTENT);
    n.addresses.length.should.be.greaterThan(cast(size_t) 0);
    n.addresses[0].host.should.equal("5.5.5.5");
    n.addresses[0].port.should.equal(cast(ushort) 100);
}

@("nat: a fresh port to every responder is RANDOM (max==1)")
unittest
{
    auto n = new Nat(true);
    n.add(to("5.5.5.5", 100), peer(1));
    n.add(to("5.5.5.5", 200), peer(2));
    n.add(to("5.5.5.5", 300), peer(3)); // same host, different port each time
    n.firewall.should.equal(FW_RANDOM);
    n.addresses.length.should.equal(cast(size_t) 1);
    n.addresses[0].host.should.equal("5.5.5.5");
    n.addresses[0].port.should.equal(cast(ushort) 0); // host only, no stable port
}

@("nat: max==2 across two hosts, both double-hit, is CONSISTENT")
unittest
{
    auto n = new Nat(true);
    n.add(to("5.5.5.5", 100), peer(1));
    n.add(to("5.5.5.5", 100), peer(2)); // 5.5.5.5:100 hits 2
    n.add(to("6.6.6.6", 100), peer(3));
    n.add(to("6.6.6.6", 100), peer(4)); // 6.6.6.6:100 hits 2
    n.firewall.should.equal(FW_CONSISTENT);
}

@("nat: max==2 on a single host with >3 samples is RANDOM")
unittest
{
    auto n = new Nat(true);
    n.add(to("5.5.5.5", 100), peer(1));
    n.add(to("5.5.5.5", 100), peer(2)); // 5.5.5.5:100 hits 2
    n.add(to("5.5.5.5", 200), peer(3));
    n.add(to("5.5.5.5", 300), peer(4)); // one host, but the port keeps moving
    n.firewall.should.equal(FW_RANDOM);
}

@("nat: a responder's retries count once (dedup by from)")
unittest
{
    auto n = new Nat(true);
    n.add(to("5.5.5.5", 100), peer(1));
    n.add(to("5.5.5.5", 100), peer(1)); // same peer again — ignored
    n.add(to("5.5.5.5", 100), peer(1));
    n.sampled.should.equal(cast(size_t) 1); // only one distinct responder counted
}
