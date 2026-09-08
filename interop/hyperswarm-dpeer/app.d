/// A D hyperswarm CLIENT: join a topic, discover the JS server announcing it,
/// connect (peer handshake + UDX stream + connection secret-stream), then send an
/// encrypted message and expect it echoed back. Proves the hyperswarm join ->
/// discover -> connect path is wire-compatible with the real hyperswarm.
/// args: <readyFile>
module app;

import hyperswarm.swarm : Hyperswarm;
import hyperswarm.connection : Connection;
import hyperswarm.cenc : Address;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import core.time : msecs;
import std.file : readText, exists;
import std.string : strip, split;
import std.conv : to;
import std.format : format;
import std.stdio : writeln;

private enum string EXPECTED = "hello hyperswarm";
private __gshared bool g_gotEcho;
private __gshared bool g_discovered;
private __gshared Hyperswarm g_swarm;

private string toHex(scope const(ubyte)[] b) nothrow
{
    string r;
    try
        foreach (x; b)
            r ~= format("%02x", x);
    catch (Exception)
    {
    }
    return r;
}

private ubyte[32] fromHex(string h)
{
    ubyte[32] o;
    foreach (i; 0 .. 32)
        o[i] = cast(ubyte) h[2 * i .. 2 * i + 2].to!ubyte(16);
    return o;
}

int main(string[] args)
{
    immutable readyFile = args[1];
    int result = 1;

    runTask(() nothrow {
        try
        {
            string line;
            for (int i = 0; i < 800 && line.length == 0; i++)
            {
                try
                    if (exists(readyFile))
                        line = readText(readyFile).strip;
                catch (Exception)
                {
                }
                if (line.length == 0)
                    sleep(20.msecs);
            }
            auto parts = line.split(" ");
            immutable bootPort = parts[0].to!ushort;
            ubyte[32] topic = fromHex(parts[1]);

            g_swarm = new Hyperswarm([Address("127.0.0.1", 4, bootPort)]);
            g_swarm.onDiscover = (ubyte[32] pk) nothrow {
                g_discovered = true;
                try
                    writeln("OK discovered peer ", toHex(pk[])[0 .. 16], "… via topic lookup");
                catch (Exception)
                {
                }
            };
            g_swarm.onConnection = (Connection c) nothrow {
                c.onData = (ubyte[] m) nothrow {
                    if (cast(string) m == EXPECTED)
                        g_gotEcho = true;
                };
                c.write(cast(const(ubyte)[]) EXPECTED);
            };
            g_swarm.join(topic, true, false); // client mode

            for (int i = 0; i < 1100 && !g_gotEcho; i++)
                sleep(10.msecs);

            if (g_gotEcho)
            {
                writeln("OK hyperswarm encrypted echo worked D<->JS!");
                result = 0; // full join -> discover -> connect -> encrypted echo
            }
            else if (g_discovered)
                writeln("FAIL discovered the peer but the connection did not echo");
            else
                writeln("FAIL did not discover the topic's peer");
            g_swarm.close();
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
