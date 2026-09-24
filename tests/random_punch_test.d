/// Holepunch Stage D: the RANDOM/birthday punch strategies the rig CANNOT
/// reproduce (no symmetric NAT on hand), so they get their coverage here via the
/// Holepuncher's beacon test-seam — no real sends. Two legs:
///   RANDOM × CONSISTENT -> _openBirthdaySockets: 256 sockets, each beaconed once
///     at TTL 5 toward the peer's fixed mapping (the birthday spray).
///   CONSISTENT × RANDOM -> _randomProbes: beacons at random ports in [1000,65536)
///     on the peer host at TTL 64.
/// Assertions run AFTER runEventLoop, never inside a fiber.
module tests.random_punch_test;

import fluent.asserts;
import core.time : msecs;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

import hyperswarm.cenc : Address;
import hyperswarm.dht.rpc : Rpc;
import hyperswarm.dht.socket_pool : SocketPool;
import hyperswarm.dht.holepuncher : Holepuncher, BIRTHDAY_SOCKETS, HOLEPUNCH_TTL, DEFAULT_TTL;
import hyperswarm.dht.connect_messages : FW_CONSISTENT, FW_RANDOM;

// --- birthday spray (RANDOM x CONSISTENT) ---
private __gshared size_t g_beaconCount;
private __gshared bool g_anyNonTtl5;
private __gshared bool g_anyNonVerified;
private __gshared size_t g_holderSnapshot;
private __gshared size_t g_poolSnapshot;
private __gshared size_t g_poolAfterDestroy;

@("holepuncher: RANDOM x CONSISTENT opens 256 birthday sockets, all TTL 5 to the peer")
unittest
{
    g_beaconCount = 0;
    g_anyNonTtl5 = false;
    g_anyNonVerified = false;
    g_holderSnapshot = 0;
    g_poolSnapshot = 0;
    g_poolAfterDestroy = 999;

    runTask(() nothrow {
        Rpc rpc;
        SocketPool pool;
        Holepuncher hp;
        try
        {
            rpc = new Rpc(0);
            pool = new SocketPool(rpc);
            hp = new Holepuncher(rpc, pool, /*isInitiator*/ true, FW_CONSISTENT);
            hp.localFirewall = FW_RANDOM;
            hp.remoteFirewall = FW_CONSISTENT;

            hp.onBeaconSent = (void* sock, Address to, int ttl) nothrow {
                g_beaconCount++;
                if (ttl != HOLEPUNCH_TTL)
                    g_anyNonTtl5 = true;
                if (to.host != "5.6.7.8" || to.port != 9000)
                    g_anyNonVerified = true;
            };

            hp.updateRemote(true, FW_CONSISTENT, [Address("5.6.7.8", 4, 9000)], "5.6.7.8");
            hp.punch();

            // openBirthdaySockets runs atomically in its fiber (no yields until
            // keepAlive's 100ms pause), so a short sleep lands after the full spray
            // but before any keepAlive beacon fires.
            sleep(30.msecs);
            g_holderSnapshot = hp.holderCount();
            g_poolSnapshot = pool.count();

            hp.destroy();
            sleep(50.msecs); // udx closes asynchronously; the loop runs the close cbs
            g_poolAfterDestroy = pool.count();
        }
        catch (Exception)
        {
        }
        try
        {
            if (rpc !is null)
                rpc.close();
        }
        catch (Exception)
        {
        }
        try
            exitEventLoop();
        catch (Exception)
        {
        }
    });
    runEventLoop();

    g_holderSnapshot.should.equal(BIRTHDAY_SOCKETS); // 256
    g_poolSnapshot.should.equal(BIRTHDAY_SOCKETS);
    g_beaconCount.should.be.greaterThan(cast(size_t) 250); // ~255 birthday beacons
    g_anyNonTtl5.should.equal(false); // the whole spray is TTL 5
    g_anyNonVerified.should.equal(false); // all aimed at the peer's fixed mapping
    g_poolAfterDestroy.should.equal(cast(size_t) 0); // destroy released every socket
}

// --- random probes (CONSISTENT x RANDOM) ---
private __gshared size_t g_rpCount;
private __gshared bool g_rpBadTtl;
private __gshared bool g_rpBadHost;
private __gshared bool g_rpBadRange;
private __gshared ushort g_rpFirstPort;
private __gshared bool g_rpPortVaried;

@("holepuncher: CONSISTENT x RANDOM sprays random ports in [1000,65536) at TTL 64")
unittest
{
    g_rpCount = 0;
    g_rpBadTtl = false;
    g_rpBadHost = false;
    g_rpBadRange = false;
    g_rpFirstPort = 0;
    g_rpPortVaried = false;

    runTask(() nothrow {
        Rpc rpc;
        SocketPool pool;
        Holepuncher hp;
        try
        {
            rpc = new Rpc(0);
            pool = new SocketPool(rpc);
            hp = new Holepuncher(rpc, pool, /*isInitiator*/ true, FW_CONSISTENT);
            hp.localFirewall = FW_CONSISTENT;
            hp.remoteFirewall = FW_RANDOM;

            hp.onBeaconSent = (void* sock, Address to, int ttl) nothrow {
                g_rpCount++;
                if (ttl != DEFAULT_TTL)
                    g_rpBadTtl = true;
                if (to.host != "5.6.7.8")
                    g_rpBadHost = true;
                if (to.port < 1000) // upper bound is ushort-max, always < 65536
                    g_rpBadRange = true;
                if (g_rpFirstPort == 0)
                    g_rpFirstPort = to.port;
                else if (to.port != g_rpFirstPort)
                    g_rpPortVaried = true;
            };

            hp.updateRemote(true, FW_RANDOM, [Address("5.6.7.8", 4, 9000)], "5.6.7.8");
            hp.punch();

            // randomProbes pauses 20ms between beacons; wait for ~40 of them.
            foreach (_; 0 .. 100)
            {
                if (g_rpCount >= 40)
                    break;
                sleep(20.msecs);
            }
            hp.destroy();
        }
        catch (Exception)
        {
        }
        try
        {
            if (rpc !is null)
                rpc.close();
        }
        catch (Exception)
        {
        }
        try
            exitEventLoop();
        catch (Exception)
        {
        }
    });
    runEventLoop();

    g_rpCount.should.be.greaterThan(cast(size_t) 30);
    g_rpBadTtl.should.equal(false); // every probe TTL 64
    g_rpBadHost.should.equal(false); // every probe to the peer host
    g_rpBadRange.should.equal(false); // ports >= 1000 (< 65536 by type)
    g_rpPortVaried.should.equal(true); // ports are randomised, not fixed
}


// punch() is idempotent (hyperdht memoises the punch promise): a replayed or
// retried round calling it again must not start a second probe loop over the
// same holders. CONSISTENT x CONSISTENT fires exactly two beacons up front (the
// fast-open ping + the first tick), so two punch() calls that started two loops
// would show four.
private __gshared size_t g_idemBeacons;
private __gshared bool g_idemFirst, g_idemSecond;

@("holepuncher: punch() twice starts one strategy (idempotent)")
unittest
{
    g_idemBeacons = 0;
    g_idemFirst = g_idemSecond = false;

    runTask(() nothrow {
        Rpc rpc;
        try
        {
            rpc = new Rpc(0);
            auto pool = new SocketPool(rpc);
            auto hp = new Holepuncher(rpc, pool, /*isInitiator*/ true, FW_CONSISTENT);
            hp.localFirewall = FW_CONSISTENT;
            hp.onBeaconSent = (void* sock, Address to, int ttl) nothrow { g_idemBeacons++; };
            hp.updateRemote(true, FW_CONSISTENT, [Address("5.6.7.8", 4, 9000)], "5.6.7.8");
            g_idemFirst = hp.punch();
            g_idemSecond = hp.punch();
            sleep(20.msecs); // both loops (if two) would have fired their first beacons
            hp.destroy();
        }
        catch (Exception)
        {
        }
        try
        {
            if (rpc !is null)
                rpc.close();
        }
        catch (Exception)
        {
        }
        try
            exitEventLoop();
        catch (Exception)
        {
        }
    });
    runEventLoop();

    g_idemFirst.should.equal(true);
    g_idemSecond.should.equal(true); // the memoised result, not a second start
    g_idemBeacons.should.equal(cast(size_t) 2); // one loop's worth, not two
}
