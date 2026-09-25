/// PunchedHandoff: the connection a hole punch forms on its own callback is owned until the
/// dial hands it over; anything not handed over is destroyed (the dial interrupted by
/// Hyperswarm.close, a timeout, a late punch, a second punch).
module tests.punch_handoff_test;

import fluent.asserts;
import hyperswarm.dht.connect : PunchedHandoff;

private final class FakeConn
{
    int destroyed;
    void destroy() nothrow { destroyed++; }
}

@("punched handoff: a taken connection is not destroyed")
unittest
{
    PunchedHandoff!FakeConn h;
    auto c = new FakeConn;
    h.formed(c);
    h.has.should.equal(true);
    h.take().should.equal(c);
    h.finish();
    c.destroyed.should.equal(0);
}

@("punched handoff: the dial ends (interrupt/timeout) before taking it -> destroyed")
unittest
{
    PunchedHandoff!FakeConn h;
    auto c = new FakeConn;
    h.formed(c);
    h.finish(); // scope(exit) of an interrupted dial
    c.destroyed.should.equal(1);
    h.has.should.equal(false);
}

@("punched handoff: a punch landing after the dial finished is destroyed at once")
unittest
{
    PunchedHandoff!FakeConn h;
    h.finish();
    auto late = new FakeConn;
    h.formed(late);
    late.destroyed.should.equal(1);
    h.has.should.equal(false);
}

@("punched handoff: a second punch while one is held is destroyed; the first survives the take")
unittest
{
    PunchedHandoff!FakeConn h;
    auto first = new FakeConn, second = new FakeConn;
    h.formed(first);
    h.formed(second);
    second.destroyed.should.equal(1);
    h.take().should.equal(first);
    h.finish();
    first.destroyed.should.equal(0);
}

@("punched handoff: after a take, a late punch is destroyed and finish destroys nothing else")
unittest
{
    PunchedHandoff!FakeConn h;
    auto c = new FakeConn;
    h.formed(c);
    cast(void) h.take();
    auto late = new FakeConn;
    h.formed(late);
    late.destroyed.should.equal(1);
    h.finish();
    c.destroyed.should.equal(0);
}
