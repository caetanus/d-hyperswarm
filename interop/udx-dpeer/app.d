/// The D side of the UDX interop: a dialer driving the vendored libudx through
/// the vibe facade, talking to the real udx-native JS echo peer. It binds a udx
/// socket, exchanges ports with the JS peer via files, connects a stream, writes a
/// message and expects it echoed back. Prints "OK" (exit 0) on a clean round-trip.
///
/// This is the phase-2 acceptance: a reliable UDX stream, wire-compatible with the
/// reference implementation.
///
/// args: <ownId> <peerId> <ownPortFile> <peerPortFile>
module app;

import hyperswarm.udx.udx;
import hyperswarm.udx.facade : Loop, uv_buf_t;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import core.time : msecs;
import core.sys.posix.sys.socket : sockaddr, sockaddr_storage, AF_INET;
import core.sys.posix.netinet.in_ : sockaddr_in;
import core.sys.posix.arpa.inet : htonl, htons, ntohs;
import std.file : write, readText, exists;
import std.conv : to;
import std.string : strip;
import std.stdio : writeln;

private __gshared bool g_gotEcho;
private enum string EXPECTED = "udx-interop-hello";

extern (C) void onSocketClose(void* s) nothrow {}
extern (C) void onStreamClose(void* s, int status) nothrow {}
extern (C) void onStreamFinalize(void* s) nothrow {}

extern (C) void onRead(void* stream, ptrdiff_t len, const(uv_buf_t)* buf) nothrow
{
    if (len <= 0)
        return;
    if (cast(string) buf.base[0 .. len] == EXPECTED)
        g_gotEcho = true;
}

int main(string[] args)
{
    if (args.length < 5)
    {
        writeln("usage: udx-interop-peer <ownId> <peerId> <ownPortFile> <peerPortFile>");
        return 2;
    }
    immutable ownId = args[1].to!uint;
    immutable peerId = args[2].to!uint;
    immutable ownPortFile = args[3];
    immutable peerPortFile = args[4];
    int result = 1;

    runTask(() nothrow {
        try
        {
            auto loop = new Loop();
            runTask(() nothrow { try loop.run(); catch (Exception) {} });

            auto udx = new ubyte[hs_udx_sizeof_udx()];
            hs_udx_init(loop.chandle, udx.ptr, null);

            auto sock = new ubyte[hs_udx_sizeof_socket()];
            hs_udx_socket_init(udx.ptr, sock.ptr, &onSocketClose);

            sockaddr_in bindv4;
            bindv4.sin_family = AF_INET;
            bindv4.sin_addr.s_addr = htonl(0x7f00_0001);
            bindv4.sin_port = 0;
            hs_udx_socket_bind(sock.ptr, cast(sockaddr*)&bindv4, 0);

            sockaddr_storage ss;
            int slen = cast(int) ss.sizeof;
            hs_udx_socket_getsockname(sock.ptr, &ss, &slen);
            immutable ownPort = ntohs((cast(sockaddr_in*)&ss).sin_port);
            write(ownPortFile, ownPort.to!string);
            writeln("D LISTEN port=", ownPort, " id=", ownId);

            // rendezvous: wait for the peer's port file
            ushort peerPort = 0;
            for (int i = 0; i < 500 && peerPort == 0; i++)
            {
                try
                    if (exists(peerPortFile))
                    {
                        auto s = readText(peerPortFile).strip;
                        if (s.length)
                            peerPort = s.to!ushort;
                    }
                catch (Exception)
                {
                }
                if (peerPort == 0)
                    sleep(20.msecs);
            }
            if (peerPort == 0)
            {
                writeln("FAIL peer port never appeared");
            }
            else
            {
                auto stream = new ubyte[hs_udx_sizeof_stream()];
                hs_udx_stream_init(udx.ptr, stream.ptr, ownId, &onStreamClose, &onStreamFinalize);
                hs_udx_stream_read_start(stream.ptr, &onRead);

                sockaddr_in peer;
                peer.sin_family = AF_INET;
                peer.sin_addr.s_addr = htonl(0x7f00_0001);
                peer.sin_port = htons(peerPort);
                hs_udx_stream_connect(stream.ptr, sock.ptr, peerId, cast(sockaddr*)&peer);
                writeln("D connected to peer port=", peerPort);

                auto wreq = new ubyte[hs_udx_stream_write_sizeof(1)];
                auto wb = uv_buf_t(cast(char*) EXPECTED.ptr, EXPECTED.length);
                hs_udx_stream_write(wreq.ptr, stream.ptr, &wb, 1, null);

                for (int i = 0; i < 400 && !g_gotEcho; i++)
                    sleep(10.msecs);

                if (g_gotEcho)
                {
                    writeln("OK udx echo D<->JS round-tripped");
                    result = 0;
                }
                else
                    writeln("FAIL no echo within timeout");
            }
            loop.stop();
        }
        catch (Exception e)
        {
            try
                writeln("FAIL exception: ", e.msg);
            catch (Exception)
            {
            }
        }
        try
            exitEventLoop();
        catch (Exception)
        {
        }
    });
    runEventLoop();
    return result;
}
