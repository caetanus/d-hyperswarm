/// Phase-2 payoff: a reliable UDX stream, end to end, D↔D, over the libuv→vibe
/// facade. Two udx sockets on localhost, a stream each; A writes "hello" over its
/// stream, B's read callback echoes it back, A's read callback sees the echo. If
/// this round-trips, the real vendored libudx is driving actual reliable streams
/// through our facade: UDP recv/send, the loop's timers (RTO/keepalive) and its
/// prepare/check hooks (packet flush / TTL drain) all working together.
///
/// Assertions run AFTER runEventLoop returns — never inside a fiber body.
module tests.udx_echo_test;

import fluent.asserts;
import hyperswarm.udx.udx;
import hyperswarm.udx.facade : Loop, uv_buf_t, uv_udp_t;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import core.time : msecs;
import core.sys.posix.sys.socket : sockaddr, sockaddr_storage, AF_INET;
import core.sys.posix.netinet.in_ : sockaddr_in;
import core.sys.posix.arpa.inet : htonl;

private __gshared bool g_gotEcho;
private __gshared ubyte[256] g_rxA;
private __gshared int g_rxALen;
private __gshared ubyte[256] g_echoData; // B's echo payload store (must persist)
private __gshared ubyte[] g_echoReq; // B's echo write request

extern (C) void onSocketClose(void* s) nothrow {}
extern (C) void onStreamClose(void* s, int status) nothrow {}
extern (C) void onStreamFinalize(void* s) nothrow {}

// B receives A's data and echoes it straight back over its own stream.
extern (C) void onReadB(void* stream, ptrdiff_t len, const(uv_buf_t)* buf) nothrow
{
    if (len <= 0)
        return;
    g_echoData[0 .. len] = cast(ubyte[]) buf.base[0 .. len];
    auto eb = uv_buf_t(cast(char*) g_echoData.ptr, len);
    hs_udx_stream_write(g_echoReq.ptr, stream, &eb, 1, null);
}

// A receives the echo.
extern (C) void onReadA(void* stream, ptrdiff_t len, const(uv_buf_t)* buf) nothrow
{
    if (len <= 0)
        return;
    g_rxALen = cast(int) len;
    g_rxA[0 .. len] = cast(ubyte[]) buf.base[0 .. len];
    g_gotEcho = true;
}

@("udx echo: a reliable stream round-trips D↔D through the facade")
unittest
{
    g_gotEcho = false;
    g_rxALen = 0;

    runTask(() nothrow {
        try
        {
            auto loop = new Loop();
            auto loopTask = runTask(() nothrow { try loop.run(); catch (Exception) {} });

            auto udx = new ubyte[hs_udx_sizeof_udx()];
            hs_udx_init(loop.chandle, udx.ptr, null);

            sockaddr_in bindv4;
            bindv4.sin_family = AF_INET;
            bindv4.sin_addr.s_addr = htonl(0x7f00_0001); // 127.0.0.1
            bindv4.sin_port = 0;

            // two sockets, each bound to an ephemeral localhost port
            auto sockA = new ubyte[hs_udx_sizeof_socket()];
            auto sockB = new ubyte[hs_udx_sizeof_socket()];
            hs_udx_socket_init(udx.ptr, sockA.ptr, &onSocketClose);
            hs_udx_socket_init(udx.ptr, sockB.ptr, &onSocketClose);
            hs_udx_socket_bind(sockA.ptr, cast(sockaddr*)&bindv4, 0);
            hs_udx_socket_bind(sockB.ptr, cast(sockaddr*)&bindv4, 0);

            sockaddr_storage addrA, addrB;
            int lenA = cast(int) addrA.sizeof, lenB = cast(int) addrB.sizeof;
            hs_udx_socket_getsockname(sockA.ptr, &addrA, &lenA);
            hs_udx_socket_getsockname(sockB.ptr, &addrB, &lenB);

            // a stream on each side (A: id 1 ↔ B: id 2)
            auto streamA = new ubyte[hs_udx_sizeof_stream()];
            auto streamB = new ubyte[hs_udx_sizeof_stream()];
            hs_udx_stream_init(udx.ptr, streamA.ptr, 1, &onStreamClose, &onStreamFinalize);
            hs_udx_stream_init(udx.ptr, streamB.ptr, 2, &onStreamClose, &onStreamFinalize);
            g_echoReq = new ubyte[hs_udx_stream_write_sizeof(1)];

            hs_udx_stream_read_start(streamA.ptr, &onReadA);
            hs_udx_stream_read_start(streamB.ptr, &onReadB);

            hs_udx_stream_connect(streamA.ptr, sockA.ptr, 2, cast(sockaddr*)&addrB);
            hs_udx_stream_connect(streamB.ptr, sockB.ptr, 1, cast(sockaddr*)&addrA);

            // A writes "hello"
            auto wreq = new ubyte[hs_udx_stream_write_sizeof(1)];
            string hello = "hello";
            auto wb = uv_buf_t(cast(char*) hello.ptr, hello.length);
            hs_udx_stream_write(wreq.ptr, streamA.ptr, &wb, 1, null);

            // let the handshake + round-trip complete
            for (int i = 0; i < 100 && !g_gotEcho; i++)
                sleep(10.msecs);

            // Tear down before stopping the loop: streams first (udx will not close a socket
            // that still carries one), then the sockets, then let their closes settle — a test
            // that just stops the loop leaves bound sockets behind for the whole suite.
            hs_udx_stream_destroy(streamA.ptr);
            hs_udx_stream_destroy(streamB.ptr);
            hs_udx_socket_close(sockA.ptr);
            hs_udx_socket_close(sockB.ptr);
            sleep(50.msecs);
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

    g_gotEcho.should.equal(true);
    (cast(string) g_rxA[0 .. g_rxALen].idup).should.equal("hello");
}
