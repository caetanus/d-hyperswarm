/// Two D hyperswarm nodes meeting on a topic through a bootstrapper: one joins in
/// server mode (announce topic + listen + accept), the other in client mode
/// (lookup + connect). They discover each other, connect, and echo an encrypted
/// message — the whole hyperswarm loop in D, end to end.
/// args: <bootPort>
module app;

import hyperswarm.swarm : Hyperswarm;
import hyperswarm.connection : Connection;
import hyperswarm.cenc : Address;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import core.time : msecs;
import std.conv : to;
import std.stdio : writeln;

private enum string EXPECTED = "hello d2d hyperswarm";
private __gshared bool g_serverGot;
private __gshared bool g_clientEcho;

int main(string[] args)
{
    immutable bootPort = args[1].to!ushort;
    int result = 1;

    runTask(() nothrow {
        try
        {
            ubyte[32] topic;
            topic[] = 0x2a;
            auto boot = [Address("127.0.0.1", 4, bootPort)];

            // server node: accept + echo
            auto srv = new Hyperswarm(boot);
            srv.onConnection = (Connection c) nothrow {
                g_serverGot = true;
                c.onData = (ubyte[] m) nothrow { c.write(m); }; // echo
            };
            srv.join(topic, false, true); // server mode

            // give the announce/listen a moment to land before the client looks up
            sleep(1500.msecs);

            // client node: discover + connect + send
            auto cli = new Hyperswarm(boot);
            cli.onConnection = (Connection c) nothrow {
                c.onData = (ubyte[] m) nothrow {
                    if (cast(string) m == EXPECTED)
                        g_clientEcho = true;
                };
                c.write(cast(const(ubyte)[]) EXPECTED);
            };
            cli.join(topic, true, false); // client mode

            for (int i = 0; i < 1200 && !g_clientEcho; i++)
                sleep(10.msecs);

            if (g_serverGot && g_clientEcho)
            {
                writeln("OK D<->D hyperswarm: discover + connect + encrypted echo!");
                result = 0;
            }
            else
                writeln("FAIL serverGot=", g_serverGot, " clientEcho=", g_clientEcho);
            cli.close();
            srv.close();
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
