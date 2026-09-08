/// The D side of the dht-rpc interop: send a FIND_NODE datagram to a real dht-rpc
/// node (over plain vibe UDP) and decode its reply. A well-formed RESPONSE with our
/// tid and the node's id proves our dht-rpc packet wire is compatible.
///
/// args: <peerPort> <readyFile>
module app;

import hyperswarm.dht.wire;
import hyperswarm.cenc : Address;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.net : listenUDP, UDPConnection, NetworkAddress, resolveHost;
import core.time : msecs, seconds;
import std.file : exists;
import std.conv : to;
import std.stdio : writeln;

int main(string[] args)
{
    if (args.length < 3)
    {
        writeln("usage: dht-interop-peer <peerPort> <readyFile>");
        return 2;
    }
    immutable peerPort = args[1].to!ushort;
    immutable readyFile = args[2];
    int result = 1;

    runTask(() nothrow {
        try
        {
            for (int i = 0; i < 500 && !exists(readyFile); i++)
                sleep(20.msecs);

            auto sock = listenUDP(0, "127.0.0.1");
            auto dst = resolveHost("127.0.0.1");
            dst.port = peerPort;

            ubyte[32] target = 0x42;
            immutable ushort tid = 0x1234;
            auto req = encodeRequest(tid, Address("127.0.0.1", 4, peerPort), FIND_NODE, target[]);
            sock.send(req, &dst);
            writeln("D-DHT sent FIND_NODE to 127.0.0.1:", peerPort);

            auto buf = new ubyte[](2048);
            auto got = sock.recv(3.seconds, buf);
            if (got.length == 0)
                writeln("FAIL no reply");
            else
            {
                auto reply = decodeReply(got);
                if (reply.tid == tid && reply.id.length == 32)
                {
                    writeln("OK dht reply: tid=", reply.tid, " id=32B closerNodes=",
                        reply.closerNodes.length, " ourAddr=", reply.to.host, ":", reply.to.port);
                    result = 0;
                }
                else
                    writeln("FAIL bad reply tid=", reply.tid, " idlen=", reply.id.length);
            }
            try
                sock.close();
            catch (Exception)
            {
            }
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
