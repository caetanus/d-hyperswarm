/// Stage A of the holepunch: the beacon primitive. The punch fires a single
/// [0x00] byte at TTL 5 (openSession) or 64 (ping) via hs_udx_socket_send_ttl —
/// a binding that did not exist before. This proves the TTL send is wired and a
/// 1-byte datagram crosses between two udx sockets (TTL 5 is ample on loopback).
///
/// Assertions run AFTER runEventLoop returns — never inside a fiber body.
module tests.udx_ttl_test;

import fluent.asserts;
import hyperswarm.udx.udx;
import hyperswarm.udx.facade : Loop, uv_buf_t;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import core.time : msecs;
import core.sys.posix.sys.socket : sockaddr, sockaddr_storage, AF_INET;
import core.sys.posix.netinet.in_ : sockaddr_in;
import core.sys.posix.arpa.inet : htonl;

private __gshared int g_rxLen = -1;
private __gshared ubyte g_rxByte = 0xFF;
private __gshared ubyte[1] g_beacon = [0]; // the HOLEPUNCH beacon, must outlive the send

extern (C) void onTtlSockClose(void* s) nothrow {}
extern (C) void onTtlSendDone(void* req, int status) nothrow {}

extern (C) void onTtlRecv(void* socket, ptrdiff_t len, const(uv_buf_t)* buf, const(void)* from) nothrow
{
    if (len == 1)
        g_rxByte = cast(ubyte) buf.base[0];
    g_rxLen = cast(int) len;
}

@("udx: a 1-byte beacon at TTL 5 crosses between two sockets (holepunch Stage A: send_ttl)")
unittest
{
    g_rxLen = -1;
    g_rxByte = 0xFF;

    runTask(() nothrow {
        try
        {
            auto loop = new Loop();
            auto loopTask = runTask(() nothrow { try loop.run(); catch (Exception) {} });

            auto udx = new ubyte[hs_udx_sizeof_udx()];
            hs_udx_init(loop.chandle, udx.ptr, null);

            sockaddr_in bindv4;
            bindv4.sin_family = AF_INET;
            bindv4.sin_addr.s_addr = htonl(0x7f00_0001);
            bindv4.sin_port = 0;

            auto sockA = new ubyte[hs_udx_sizeof_socket()];
            auto sockB = new ubyte[hs_udx_sizeof_socket()];
            hs_udx_socket_init(udx.ptr, sockA.ptr, &onTtlSockClose);
            hs_udx_socket_init(udx.ptr, sockB.ptr, &onTtlSockClose);
            hs_udx_socket_bind(sockA.ptr, cast(sockaddr*)&bindv4, 0);
            hs_udx_socket_bind(sockB.ptr, cast(sockaddr*)&bindv4, 0);
            hs_udx_socket_recv_start(sockB.ptr, &onTtlRecv);

            sockaddr_storage addrB;
            int lenB = cast(int) addrB.sizeof;
            hs_udx_socket_getsockname(sockB.ptr, &addrB, &lenB);

            auto req = new ubyte[hs_udx_sizeof_socket_send()];
            auto b = uv_buf_t(cast(char*) g_beacon.ptr, 1);
            hs_udx_socket_send_ttl(req.ptr, sockA.ptr, &b, 1, cast(sockaddr*)&addrB, 5, &onTtlSendDone);

            for (int i = 0; i < 200 && g_rxLen < 0; i++)
                sleep(10.msecs);

            // Close the sockets before stopping the loop, so none outlives the test.
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

    g_rxLen.should.equal(1); // the beacon arrived, exactly one byte
    g_rxByte.should.equal(cast(ubyte) 0); // and it is the [0x00] beacon
}
