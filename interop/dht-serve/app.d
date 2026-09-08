/// A direct D↔D connect: a D Server accepts an incoming peer handshake and a D
/// client connects straight to its address (no DHT discovery / relay). Proves the D
/// server side — IK responder, UDX stream accept (firewall), connection
/// secret-stream — against our own client, end to end with an encrypted echo.
module app;

import hyperswarm.dht.node : Dht;
import hyperswarm.dht.serve : Server;
import hyperswarm.dht.connect : connectHandshakeTo;
import hyperswarm.connection : Connection, hsConnRead, hsConnClose, hsConnFinalize;
import hyperswarm.udx.udx;
import hyperswarm.noise.stream : SecretStream;
import hyperswarm.noise.crypto : ed25519RandomKeypair;
import hyperswarm.cenc : Address;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import core.time : msecs;
import core.sys.posix.sys.socket : sockaddr, AF_INET;
import core.sys.posix.netinet.in_ : sockaddr_in;
import core.sys.posix.arpa.inet : htons, inet_addr;
import std.random : uniform;
import std.string : toStringz;
import std.stdio : writeln;

private enum string EXPECTED = "hello d2d over hyperswarm";
private __gshared bool g_serverGotConn;
private __gshared bool g_clientGotEcho;

int main(string[] args)
{
    int result = 1;
    runTask(() nothrow {
        try
        {
            // ── server ──
            auto serverKp = ed25519RandomKeypair();
            auto serverDht = new Dht([]);
            auto server = new Server(serverDht, serverKp);
            server.onConnection = (Connection c) nothrow {
                g_serverGotConn = true;
                c.onData = (ubyte[] m) nothrow { c.write(m); }; // echo
            };

            // ── client: connect directly to the server's address ──
            auto clientKp = ed25519RandomKeypair();
            auto clientDht = new Dht([]);
            auto serverAddr = Address("127.0.0.1", 4, serverDht.rpc.localPort);
            auto clientUdxAddr = Address("127.0.0.1", 4, clientDht.rpc.localPort);
            immutable uint ourUdxId = cast(uint) uniform(1, uint.max);

            auto ch = connectHandshakeTo(clientDht, serverKp.publicKey, clientKp,
                serverAddr, clientUdxAddr, ourUdxId);
            writeln("OK client handshake completed with the D server (serverUdxId=",
                ch.serverPayload.udx.id, ")");

            auto stream = new ubyte[](hs_udx_sizeof_stream());
            hs_udx_stream_init(clientDht.rpc.udxPtr, stream.ptr, ourUdxId, &hsConnClose, &hsConnFinalize);
            hs_udx_stream_read_start(stream.ptr, &hsConnRead);
            auto ss = SecretStream.fromHandshake(true, ch.hs.tx, ch.hs.rx, ch.hs.hash,
                ch.hs.remotePublicKey);
            auto conn = new Connection(clientDht.rpc.udxPtr, stream.ptr, ss, ch.hs.remotePublicKey);
            conn.onData = (ubyte[] m) nothrow {
                if (cast(string) m == EXPECTED)
                    g_clientGotEcho = true;
            };
            conn.onOpen = () nothrow { conn.write(cast(const(ubyte)[]) EXPECTED); };

            auto target = ch.serverPayload.addresses4.length ? ch.serverPayload.addresses4[0]
                : ch.serverAddress;
            sockaddr_in peer;
            peer.sin_family = AF_INET;
            peer.sin_addr.s_addr = inet_addr(target.host.toStringz);
            peer.sin_port = htons(target.port);
            hs_udx_stream_connect(stream.ptr, clientDht.rpc.sockPtr, ch.serverPayload.udx.id,
                cast(sockaddr*)&peer);
            conn.start();

            for (int i = 0; i < 800 && !g_clientGotEcho; i++)
                sleep(10.msecs);

            if (g_serverGotConn && g_clientGotEcho)
            {
                writeln("OK D<->D encrypted echo over the connection worked!");
                result = 0;
            }
            else
                writeln("FAIL serverGotConn=", g_serverGotConn, " clientGotEcho=", g_clientGotEcho);
            clientDht.close();
            serverDht.close();
        }
        catch (Exception e)
        {
            try
                writeln("FAIL ", e.msg);
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
