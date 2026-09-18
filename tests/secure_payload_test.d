/// Holepunch Stage D: SecurePayload round-trips a holepunch payload under the
/// shared secret, rejects a wrong secret, and mints stable per-address tokens.
module tests.secure_payload_test;

import fluent.asserts;
import hyperswarm.dht.secure_payload : SecurePayload;
import hyperswarm.dht.connect_messages : HolepunchPayload;
import hyperswarm.cenc : Address;

private HolepunchPayload samplePayload()
{
    HolepunchPayload p;
    p.firewall = 2; // CONSISTENT
    p.round = 3;
    p.punching = true;
    p.addresses = [Address("1.2.3.4", 4, 5000)];
    p.token = new ubyte[32];
    foreach (i, ref b; p.token)
        b = cast(ubyte)(i + 1);
    return p;
}

@("secure payload: encrypt then decrypt round-trips under the shared secret")
unittest
{
    ubyte[32] secret = 7;
    auto sp = new SecurePayload(secret);

    auto p = samplePayload();
    auto sealed = sp.encrypt(p);
    sealed.length.should.be.greaterThan(cast(size_t)(24 + 16)); // nonce + mac + body

    auto opened = sp.decrypt(sealed);
    opened.isNull.should.equal(false);
    opened.get.firewall.should.equal(cast(uint) 2);
    opened.get.round.should.equal(cast(uint) 3);
    opened.get.punching.should.equal(true);
    opened.get.addresses.length.should.equal(cast(size_t) 1);
    opened.get.addresses[0].host.should.equal("1.2.3.4");
    opened.get.addresses[0].port.should.equal(cast(ushort) 5000);
    (opened.get.token == p.token).should.equal(true);
}

@("secure payload: a different secret cannot open the box")
unittest
{
    ubyte[32] a = 7;
    ubyte[32] b = 9;
    auto sender = new SecurePayload(a);
    auto other = new SecurePayload(b);

    auto sealed = sender.encrypt(samplePayload());
    other.decrypt(sealed).isNull.should.equal(true); // MAC fails under the wrong key
}

@("secure payload: tokens are stable per host and differ across hosts")
unittest
{
    ubyte[32] secret = 3;
    auto sp = new SecurePayload(secret);

    auto t1 = sp.token(Address("5.5.5.5", 4, 100));
    auto t2 = sp.token(Address("5.5.5.5", 4, 999)); // same host, different port
    auto t3 = sp.token(Address("6.6.6.6", 4, 100));

    t1.length.should.equal(cast(size_t) 32);
    (t1 == t2).should.equal(true); // keyed on host only
    (t1 == t3).should.equal(false); // different host
}
