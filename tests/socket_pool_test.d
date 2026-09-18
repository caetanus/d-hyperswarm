/// Holepunch Stage B: the SocketPool lifecycle over a real udx instance (no
/// network). A pool socket is a real udx socket on the Rpc's instance, registered
/// so its replies reach the Rpc; acquire/release/closeAll track them.
///
/// Assertions run AFTER runEventLoop returns — never inside a fiber body.
module tests.socket_pool_test;

import fluent.asserts;
import hyperswarm.dht.rpc : Rpc;
import hyperswarm.dht.socket_pool : SocketPool;
import vibe.core.core : runTask, runEventLoop, exitEventLoop;

private __gshared bool g_ptrOk;
private __gshared size_t g_c1, g_c2, g_c3, g_c4;

@("socket pool: acquire binds+registers, release/closeAll free (holepunch Stage B)")
unittest
{
    g_ptrOk = false;
    g_c1 = g_c2 = g_c3 = g_c4 = size_t.max;

    runTask(() nothrow {
        try
        {
            auto rpc = new Rpc(0); // ephemeral local udx socket; no network
            scope (exit)
                rpc.close();
            auto pool = new SocketPool(rpc);

            auto s1 = pool.acquire();
            g_ptrOk = s1 !is null;
            g_c1 = pool.count();

            auto s2 = pool.acquire();
            g_c2 = pool.count();

            pool.release(s1);
            g_c3 = pool.count();

            pool.closeAll();
            g_c4 = pool.count();
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

    g_ptrOk.should.equal(true);
    g_c1.should.equal(cast(size_t) 1);
    g_c2.should.equal(cast(size_t) 2);
    g_c3.should.equal(cast(size_t) 1); // release dropped one
    g_c4.should.equal(cast(size_t) 0); // closeAll freed the rest
}
