/// Full connect-by-key D→JS: find the server via the DHT, run the IK peer handshake,
/// open a UDX stream to it and run secret-stream (from the handshake keys) over that
/// stream — then echo an encrypted message. Proves the whole hyperdht connect path
/// against a real hyperdht server. args: <bootPort> <readyFile>
module app;

import hyperswarm.dht.node : Dht;
import hyperswarm.dht.connect : connectHandshake;
import hyperswarm.udx.udx; // hs_udx_*
import hyperswarm.udx.facade : Loop, uv_buf_t;
import hyperswarm.noise.stream : SecretStream;
import hyperswarm.noise.crypto : ed25519RandomKeypair;
import hyperswarm.cenc : Address;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import core.time : msecs;
import core.sys.posix.sys.socket : sockaddr, sockaddr_storage, AF_INET;
import core.sys.posix.netinet.in_ : sockaddr_in;
import core.sys.posix.arpa.inet : htonl, htons, ntohs;
import std.file : readText, exists;
import std.string : strip, split;
import std.conv : to;
import std.random : uniform;
import std.stdio : writeln;

private enum string EXPECTED = "hello over hyperdht connect";

private __gshared SecretStream g_ss;
private __gshared void* g_stream;
private __gshared bool g_gotEcho;
private __gshared bool g_sent;
private __gshared ubyte[][] g_keep; // keep write bufs/reqs alive until acked

private void writeToStream(ubyte[] data) nothrow
{
    try
    {
        auto req = new ubyte[](hs_udx_stream_write_sizeof(1));
        auto d = data.dup;
        g_keep ~= req;
        g_keep ~= d;
        auto b = uv_buf_t(cast(char*) d.ptr, d.length);
        hs_udx_stream_write(req.ptr, g_stream, &b, 1, null);
    }
    catch (Exception)
    {
    }
}

extern (C) void onStreamRead(void* stream, ptrdiff_t len, const(uv_buf_t)* buf) nothrow
{
    if (len <= 0)
        return;
    try
    {
        auto r = g_ss.feed(cast(ubyte[]) buf.base[0 .. len]);
        if (r.toSend.length)
            writeToStream(r.toSend);
        foreach (m; r.messages)
            if (cast(string) m == EXPECTED)
                g_gotEcho = true;
        if (g_ss.opened && !g_sent)
        {
            writeToStream(g_ss.write(cast(const(ubyte)[]) EXPECTED));
            g_sent = true;
        }
    }
    catch (Exception)
    {
    }
}

extern (C) void onSockClose(void* s) nothrow {}
extern (C) void onStreamClose(void* s, int st) nothrow {}
extern (C) void onStreamFinalize(void* s) nothrow {}

private ubyte[32] fromHex(string h)
{
    ubyte[32] o;
    foreach (i; 0 .. 32)
        o[i] = cast(ubyte) h[2 * i .. 2 * i + 2].to!ubyte(16);
    return o;
}

int main(string[] args)
{
    immutable bootPort = args[1].to!ushort;
    immutable readyFile = args[2];
    int result = 1;

    runTask(() nothrow {
        try
        {
            string line;
            for (int i = 0; i < 800 && line.length == 0; i++)
            {
                try if (exists(readyFile)) line = readText(readyFile).strip;
                catch (Exception) {}
                if (line.length == 0) sleep(20.msecs);
            }
            ubyte[32] pubkey = fromHex(line.split(" ")[1]);

            // facade UDX socket for the connection stream
            auto loop = new Loop();
            runTask(() nothrow { try loop.run(); catch (Exception) {} });
            auto udx = new ubyte[](hs_udx_sizeof_udx());
            hs_udx_init(loop.chandle, udx.ptr, null);
            auto sock = new ubyte[](hs_udx_sizeof_socket());
            hs_udx_socket_init(udx.ptr, sock.ptr, &onSockClose);
            sockaddr_in bindv4;
            bindv4.sin_family = AF_INET;
            bindv4.sin_addr.s_addr = htonl(0x7f00_0001);
            bindv4.sin_port = 0;
            hs_udx_socket_bind(sock.ptr, cast(sockaddr*)&bindv4, 0);
            sockaddr_storage ss;
            int sl = cast(int) ss.sizeof;
            hs_udx_socket_getsockname(sock.ptr, &ss, &sl);
            immutable udxPort = ntohs((cast(sockaddr_in*)&ss).sin_port);
            immutable uint ourUdxId = cast(uint) uniform(1, uint.max);

            // DHT peer handshake (over the RPC socket)
            auto dht = new Dht([Address("127.0.0.1", 4, bootPort)]);
            auto kp = ed25519RandomKeypair();
            auto conn = connectHandshake(dht, pubkey, kp, Address("127.0.0.1", 4, udxPort), ourUdxId);
            writeln("OK connect handshake completed: server=", conn.serverAddress.host, ":",
                conn.serverAddress.port, " serverUdxId=", conn.serverPayload.udx.id);

            // UDX stream + secret-stream from the handshake keys
            auto stream = new ubyte[](hs_udx_sizeof_stream());
            g_stream = stream.ptr;
            hs_udx_stream_init(udx.ptr, stream.ptr, ourUdxId, &onStreamClose, &onStreamFinalize);
            hs_udx_stream_read_start(stream.ptr, &onStreamRead);
            g_ss = SecretStream.fromHandshake(true, conn.hs.tx, conn.hs.rx, conn.hs.hash,
                conn.hs.remotePublicKey);

            sockaddr_in peer;
            peer.sin_family = AF_INET;
            peer.sin_addr.s_addr = htonl(0x7f00_0001);
            peer.sin_port = htons(conn.serverAddress.port);
            hs_udx_stream_connect(stream.ptr, sock.ptr, conn.serverPayload.udx.id, cast(sockaddr*)&peer);

            writeToStream(g_ss.start()); // secret-stream setup frame

            for (int i = 0; i < 200 && !g_gotEcho; i++)
                sleep(10.msecs);

            if (g_gotEcho)
            {
                writeln("OK encrypted echo over the connect UDX stream worked D<->JS!");
                result = 0; // the full connect-by-key path is proven end to end
            }
            else
                writeln("FAIL encrypted stream did not echo");
            dht.close();
        }
        catch (Exception e) { try writeln("FAIL ", e.msg); catch (Exception) {} }
        try exitEventLoop(); catch (Exception) {}
    });
    runEventLoop();
    return result;
}
