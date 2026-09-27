/// HTTP (any TCP) between two peers over ONE hyperswarm connection: protomux channels
/// carrying hyperswarm.streams byte streams, one per TCP connection.
///
///   http-bridge serve   --bootstrap H:P --topic HEX --service web=127.0.0.1:8000
///   http-bridge forward --bootstrap H:P --topic HEX --service web --port 18080
///
/// `serve` announces the topic and answers streams for its services; `forward` finds
/// it and listens on 127.0.0.1:PORT — a browser there talks to the other peer's server.
module app;

import hyperswarm.swarm : Hyperswarm;
import hyperswarm.connection : Connection;
import hyperswarm.cenc : Address;
import hyperswarm.protomux : Protomux;
import hyperswarm.streams : serveTcp, forwardTcp;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import std.getopt : getopt;
import std.conv : to;
import std.stdio : writeln, stdout;
import std.string : indexOf;
import std.algorithm : splitter;

int main(string[] args)
{
    string mode = args.length > 1 ? args[1] : "";
    string boot, topicHex, port;
    string[] service;
    getopt(args, "bootstrap", &boot, "topic", &topicHex, "service", &service, "port", &port);
    ubyte[32] topic;
    foreach (i; 0 .. 32)
        topic[i] = topicHex[2 * i .. 2 * i + 2].to!ubyte(16);
    immutable k = boot.indexOf(':');
    auto seeds = [Address(boot[0 .. k], 4, boot[k + 1 .. $].to!ushort)];

    Protomux current;   // the mux of the live connection (null while none)
    runTask(() nothrow {
        try
        {
            auto swarm = new Hyperswarm(seeds);
            swarm.onConnection = (Connection c) nothrow {
                try
                {
                    auto mux = new Protomux((const(ubyte)[] f) nothrow { c.write(f); });
                    // a protocol violation from the peer tears the whole connection down
                    mux.destroyer = (string why) nothrow { c.destroy(); };
                    c.onData = (ubyte[] m) nothrow {
                        try
                            mux.onFrame(m);
                        catch (Exception)
                        {
                        }
                    };
                    c.onClose = () nothrow {
                        try
                            mux.shutdown();
                        catch (Exception)
                        {
                        }
                        if (current is mux)
                            current = null;
                    };
                    if (mode == "serve")
                    {
                        string[string] map;
                        foreach (s; service)
                        {
                            immutable e = s.indexOf('=');
                            map[s[0 .. e]] = s[e + 1 .. $];
                        }
                        serveTcp(mux, map);
                    }
                    current = mux;
                    writeln(mode, ": connected");
                    stdout.flush();
                }
                catch (Exception e)
                {
                }
            };
            if (mode == "serve")
                swarm.join(topic, false, true);
            else
            {
                swarm.join(topic, true, false);
                forwardTcp(() => current, service[0], port.to!ushort);
                writeln("forward: listening on 127.0.0.1:", port);
                stdout.flush();
            }
        }
        catch (Exception e)
        {
            try
                writeln("FAIL ", e.msg);
            catch (Exception)
            {
            }
            try
                exitEventLoop();
            catch (Exception)
            {
            }
        }
    });
    return runEventLoop();
}
