/// Holepunch Stage B: the SocketPool lifecycle over a real udx instance (no
/// network). A pool socket is a real udx socket on the Rpc's instance, registered
/// so its replies reach the Rpc; acquire/release/closeAll track them.
///
/// Assertions run AFTER runEventLoop returns — never inside a fiber body.
module tests.socket_pool_test;

import fluent.asserts;
import hyperswarm.dht.rpc : Rpc;
import hyperswarm.dht.socket_pool : SocketPool;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import core.time : msecs;

private __gshared bool g_ptrOk;
private __gshared size_t g_c1, g_c2, g_c3, g_c4, g_freed;

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
            g_c3 = pool.openCount(); // closed now; its memory goes at udx's close cb

            pool.closeAll();
            g_c4 = pool.openCount();
            sleep(50.msecs); // the loop runs the close callbacks
            g_freed = pool.count();
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
    g_freed.should.equal(cast(size_t) 0); // and udx's close callbacks released the memory
}

// A punched hole is a pool socket with a udx stream on it: udx refuses to close
// it (UV_EBUSY) while the stream lives, so release() must say so and keep the
// socket owned; lent to the connection, it is closed the moment the stream is
// gone (giveBack from the stream's close callback) — never leaked, never freed
// under udx's feet.
private __gshared bool g_busyRelease, g_lentAfter, g_ownsWhileLent, g_freeRelease;
private __gshared size_t g_openAfterGiveBack, g_countAfterClose;

extern (C) void spNoopClose(void* stream, int status) nothrow {}
extern (C) void spNoopFinalize(void* stream) nothrow {}

@("socket pool: a socket carrying a stream stays owned on release and closes on giveBack")
unittest
{
    import hyperswarm.udx.udx;
    import core.sys.posix.sys.socket : sockaddr, AF_INET;
    import core.sys.posix.netinet.in_ : sockaddr_in;
    import core.sys.posix.arpa.inet : htons, htonl;

    g_busyRelease = g_lentAfter = g_ownsWhileLent = g_freeRelease = false;
    g_openAfterGiveBack = g_countAfterClose = size_t.max;

    runTask(() nothrow {
        try
        {
            auto rpc = new Rpc(0);
            scope (exit)
                rpc.close();
            auto pool = new SocketPool(rpc);
            auto s = pool.acquire();

            // a stream connected over this socket (to nowhere: no packet is needed)
            auto stream = new ubyte[](hs_udx_sizeof_stream());
            hs_udx_stream_init(rpc.udxPtr, stream.ptr, 7, &spNoopClose, &spNoopFinalize);
            sockaddr_in to;
            to.sin_family = AF_INET;
            to.sin_addr.s_addr = htonl(0x7f00_0001);
            to.sin_port = htons(9);
            hs_udx_stream_connect(stream.ptr, s, 8, cast(sockaddr*)&to);

            g_busyRelease = !pool.release(s); // UV_EBUSY: still ours
            pool.lend(s);
            g_lentAfter = pool.isLent(s);
            g_ownsWhileLent = pool.owns(s);

            hs_udx_stream_destroy(stream.ptr); // unlinks the stream from the socket
            sleep(20.msecs);
            pool.giveBack(s); // what the connection's close callback does
            g_openAfterGiveBack = pool.openCount();
            sleep(50.msecs);
            g_countAfterClose = pool.count();
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

    g_busyRelease.should.equal(true);
    g_lentAfter.should.equal(true);
    g_ownsWhileLent.should.equal(true);
    g_openAfterGiveBack.should.equal(cast(size_t) 0); // closed once the stream was gone
    g_countAfterClose.should.equal(cast(size_t) 0); // and freed at udx's close callback
}
