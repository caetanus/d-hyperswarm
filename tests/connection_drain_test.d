/// The drain guarantee, over real udx (no node): two Connections on a localhost
/// udx stream pair complete the secret-stream handshake, then one writes a burst
/// bigger than a single window and calls flush(). flush() must not return until
/// every write is acked, and by then the receiver must hold every byte — this is
/// exactly what a big transfer needs so closeGracefully() doesn't drop the tail.
///
/// Assertions run AFTER runEventLoop returns — never inside a fiber body.
module tests.connection_drain_test;

import fluent.asserts;
import hyperswarm.udx.udx;
import hyperswarm.udx.facade : Loop, uv_buf_t;
import hyperswarm.connection : Connection, hsConnRead, hsConnClose, hsConnFinalize;
import hyperswarm.noise.stream : SecretStream;
import hyperswarm.noise.crypto : ed25519Keypair, Keypair;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import core.time : msecs, seconds;
import core.sys.posix.sys.socket : sockaddr, sockaddr_storage, AF_INET;
import core.sys.posix.netinet.in_ : sockaddr_in;
import core.sys.posix.arpa.inet : htonl;

private enum chunks = 48;
private enum chunkSize = 8192; // 384 KiB total — many windows' worth

private __gshared bool g_aOpen, g_bOpen, g_flushed;
private __gshared size_t g_pendingAfterBurst, g_rxBytes, g_rxMsgs;

private Keypair kp(ubyte v)
{
    ubyte[32] s = v;
    return ed25519Keypair(s[]);
}

@("connection drain: flush waits for a write burst to be fully delivered")
unittest
{
    g_aOpen = g_bOpen = g_flushed = false;
    g_pendingAfterBurst = g_rxBytes = g_rxMsgs = 0;

    runTask(() nothrow {
        try
        {
            auto loop = new Loop();
            runTask(() nothrow { try loop.run(); catch (Exception) {} });

            auto udx = new ubyte[hs_udx_sizeof_udx()];
            hs_udx_init(loop.chandle, udx.ptr, null);

            sockaddr_in bindv4;
            bindv4.sin_family = AF_INET;
            bindv4.sin_addr.s_addr = htonl(0x7f00_0001);
            bindv4.sin_port = 0;

            auto sockA = new ubyte[hs_udx_sizeof_socket()];
            auto sockB = new ubyte[hs_udx_sizeof_socket()];
            hs_udx_socket_init(udx.ptr, sockA.ptr, &onSockClose);
            hs_udx_socket_init(udx.ptr, sockB.ptr, &onSockClose);
            hs_udx_socket_bind(sockA.ptr, cast(sockaddr*)&bindv4, 0);
            hs_udx_socket_bind(sockB.ptr, cast(sockaddr*)&bindv4, 0);

            sockaddr_storage addrA, addrB;
            int lenA = cast(int) addrA.sizeof, lenB = cast(int) addrB.sizeof;
            hs_udx_socket_getsockname(sockA.ptr, &addrA, &lenA);
            hs_udx_socket_getsockname(sockB.ptr, &addrB, &lenB);

            auto streamA = new ubyte[hs_udx_sizeof_stream()];
            auto streamB = new ubyte[hs_udx_sizeof_stream()];
            hs_udx_stream_init(udx.ptr, streamA.ptr, 1, &hsConnClose, &hsConnFinalize);
            hs_udx_stream_init(udx.ptr, streamB.ptr, 2, &hsConnClose, &hsConnFinalize);
            hs_udx_stream_read_start(streamA.ptr, &hsConnRead);
            hs_udx_stream_read_start(streamB.ptr, &hsConnRead);
            hs_udx_stream_connect(streamA.ptr, sockA.ptr, 2, cast(sockaddr*)&addrB);
            hs_udx_stream_connect(streamB.ptr, sockB.ptr, 1, cast(sockaddr*)&addrA);

            auto connA = new Connection(udx.ptr, streamA.ptr, new SecretStream(true, kp(1)), kp(2).publicKey);
            auto connB = new Connection(udx.ptr, streamB.ptr, new SecretStream(false, kp(2)), kp(1).publicKey);
            connA.onOpen = () nothrow { g_aOpen = true; };
            connB.onOpen = () nothrow { g_bOpen = true; };
            connB.onData = (ubyte[] m) nothrow { g_rxBytes += m.length; g_rxMsgs++; };

            connB.start(); // responder inits Noise (sends nothing)
            connA.start(); // initiator sends the first handshake frame
            for (int i = 0; i < 300 && !(g_aOpen && g_bOpen); i++)
                sleep(10.msecs);

            // Fire the whole burst without yielding, so it is all queued at once.
            auto chunk = new ubyte[chunkSize];
            foreach (j, ref b; chunk)
                b = cast(ubyte)(j & 0xff);
            foreach (_; 0 .. chunks)
                connA.write(chunk);
            g_pendingAfterBurst = connA.pendingWrites();

            g_flushed = connA.flush(20.seconds);
            // flush returning true means everything is acked; the receiver's
            // callbacks for the last frames may still be a turn behind.
            for (int i = 0; i < 100 && g_rxBytes < chunks * chunkSize; i++)
                sleep(10.msecs);

            loop.stop();
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

    g_aOpen.should.equal(true);
    g_bOpen.should.equal(true);
    (g_pendingAfterBurst > 0).should.equal(true); // the burst really was in flight
    g_flushed.should.equal(true); // flush drained it
    g_rxMsgs.should.equal(chunks); // every message
    g_rxBytes.should.equal(cast(size_t)(chunks * chunkSize)); // every byte
}

extern (C) void onSockClose(void* s) nothrow
{
}
