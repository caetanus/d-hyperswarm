/// A D hyperswarm SERVER on a topic: join in server mode (announce the topic +
/// listen + accept) and echo on every connection. A real JS hyperswarm client
/// joins the same topic, discovers us, and connects — proving the D hyperswarm
/// server side is wire-compatible with the real hyperswarm.
/// args: <bootPort> <readyFile>
module app;

import hyperswarm.swarm : Hyperswarm;
import hyperswarm.connection : Connection;
import hyperswarm.cenc : Address;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import core.time : msecs;
import std.file : write;
import std.conv : to;
import std.format : format;
import std.stdio : writeln;

private __gshared Hyperswarm g_swarm;

int main(string[] args)
{
    immutable bootPort = args[1].to!ushort;
    immutable readyFile = args[2];

    runTask(() nothrow {
        try
        {
            ubyte[32] topic;
            topic[] = 0x2a;
            g_swarm = new Hyperswarm([Address("127.0.0.1", 4, bootPort)]);
            g_swarm.onConnection = (Connection c) nothrow {
                try
                    writeln("OK D hyperswarm server accepted a connection");
                catch (Exception)
                {
                }
                c.onData = (ubyte[] m) nothrow { c.write(m); }; // echo
            };
            g_swarm.join(topic, false, true); // server mode: announce + listen + accept

            string hex;
            foreach (b; g_swarm.keyPair.publicKey)
                hex ~= format("%02x", b);
            // give announce/listen a moment to land, then signal ready
            sleep(1500.msecs);
            write(readyFile, hex);
            writeln("D hyperswarm server up, announced topic + self");

            for (int i = 0; i < 6000; i++)
                sleep(100.msecs);
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
    return 0;
}
