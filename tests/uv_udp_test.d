/// UDP through the libuv→vibe facade end to end: two sockets bound via __d_hsuv_udp_*,
/// one sends with __d_hsuv_udp_try_send (the raw non-blocking sendmsg path libudx uses
/// as its fast path), the other receives via the reader fiber that drives the
/// alloc_cb + recv_cb callbacks on the vibe loop. This is the socket layer udx's
/// packets will ride on.
///
/// Assertions run AFTER runEventLoop returns — never inside a fiber body.
module tests.uv_udp_test;

import fluent.asserts;
import hyperswarm.udx.facade;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import core.time : msecs;
import core.sys.posix.sys.socket : sockaddr, sockaddr_storage, AF_INET;
import core.sys.posix.netinet.in_ : sockaddr_in;
import core.sys.posix.arpa.inet : htonl;

private __gshared ubyte[65536] g_alloc;
private __gshared ubyte[2048] g_rx;
private __gshared int g_rxlen;

extern (C) void allocCb(uv_handle_t* h, size_t suggested, uv_buf_t* buf) nothrow
{
    buf.base = cast(char*) g_alloc.ptr;
    buf.len = g_alloc.length;
}

extern (C) void recvCb(uv_handle_t* h, ptrdiff_t nread, const(uv_buf_t)* buf,
    const(sockaddr)* addr, uint flags) nothrow
{
    if (nread > 0)
    {
        g_rxlen = cast(int) nread;
        g_rx[0 .. nread] = cast(ubyte[]) buf.base[0 .. nread];
    }
}

@("uv facade: a datagram sent through the facade is received on the vibe loop")
unittest
{
    g_rxlen = 0;

    runTask(() nothrow {
        try
        {
            auto loop = new Loop();

            sockaddr_in bindv4;
            bindv4.sin_family = AF_INET;
            bindv4.sin_addr.s_addr = htonl(0x7f00_0001); // 127.0.0.1
            bindv4.sin_port = 0; // ephemeral

            // receiver
            auto rx = new uv_udp_t;
            __d_hsuv_udp_init(loop.chandle, rx);
            __d_hsuv_udp_bind(rx, cast(sockaddr*)&bindv4, 0);
            sockaddr_storage rxname;
            int rxnamelen = cast(int) rxname.sizeof;
            __d_hsuv_udp_getsockname(rx, &rxname, &rxnamelen);
            __d_hsuv_udp_recv_start(rx, &allocCb, &recvCb);

            // sender
            auto tx = new uv_udp_t;
            __d_hsuv_udp_init(loop.chandle, tx);
            __d_hsuv_udp_bind(tx, cast(sockaddr*)&bindv4, 0);

            auto loopTask = runTask(() nothrow { try loop.run(); catch (Exception) {} });

            sleep(25.msecs); // let the reader arm
            string payload = "hello";
            auto b = uv_buf_t(cast(char*) payload.ptr, payload.length);
            __d_hsuv_udp_try_send(tx, &b, 1, cast(sockaddr*)&rxname);

            sleep(120.msecs);
            // close both handles (the reader is woken and the fds released) before stopping
            __d_hsuv_close(rx, null);
            __d_hsuv_close(tx, null);
            sleep(20.msecs);
            loop.stop();
            loopTask.join(); // let the runner return, so no task outlives the test
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

    g_rxlen.should.equal(5);
    (cast(string) g_rx[0 .. 5].idup).should.equal("hello");
}

