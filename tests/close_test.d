/// Teardown-race coverage for the shutdown ownership added in the Codex hardening
/// loop: two DHT servers in ONE process, closed independently, must not hang, must
/// not self-join, and closing one must not disturb the other. The whole test
/// completing (exitEventLoop reached, no deadlock) is the assertion — the close
/// paths (Server.close draining accepted/g_incoming by owner, the Rpc.close
/// loop-drain-stop-join barrier + UV_EBUSY retry) would otherwise hang here.
///
/// Assertions run AFTER runEventLoop returns — never inside a fiber body.
module tests.close_test;

import fluent.asserts;
import core.time : msecs;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import hyperswarm.dht.node : Dht;
import hyperswarm.dht.serve : Server;
import hyperswarm.noise.crypto : ed25519Keypair, Keypair;
import hyperswarm.cenc : Address;

private __gshared bool g_reachedEnd;
private __gshared bool g_secondAlive;

private Keypair kp(ubyte v) nothrow
{
    try
    {
        ubyte[32] s = v;
        return ed25519Keypair(s[]);
    }
    catch (Exception)
        assert(false);
}

@("teardown: two DHT servers in one process close independently without hanging")
unittest
{
    g_reachedEnd = false;
    g_secondAlive = false;

    runTask(() nothrow {
        try
        {
            // No bootstrap: no real network, but the full object graph (Rpc + Loop
            // runner fiber, Server) is built and then torn down — which is what the
            // new close barrier has to survive.
            auto a = new Dht([]);
            auto sa = new Server(a, kp(1));
            auto b = new Dht([]);
            auto sb = new Server(b, kp(2));

            sleep(20.msecs); // let both loop runners spin up

            // Close the FIRST swarm's server + dht. The second must be untouched.
            sa.close();
            a.close();
            g_secondAlive = (b.localPort != 0); // b still usable after a's teardown

            // Now close the second. If either close self-joined or dead-locked in the
            // loop-drain barrier, we never get past here.
            sb.close();
            b.close();

            g_reachedEnd = true;
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

    g_secondAlive.should.equal(true); // closing A left B alive (cross-instance isolation)
    g_reachedEnd.should.equal(true); // both closes returned; no hang, no self-join abort
}
