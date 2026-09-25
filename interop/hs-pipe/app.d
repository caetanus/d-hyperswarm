/// The hyperswarm rendezvous at the TOPIC level — exactly what an application does
/// (photo-wagon's HsTransport): the server joins a topic in server mode (announce +
/// listen), the client joins it as a client (lookup + connect-by-key, hole punch
/// when NAT'd), on the PUBLIC hyperdht. The connection is then held to the pipe
/// yardstick: a burn with an ack, then a hold with pings.
///
///   hs-pipe --role server --topic <word>
///   hs-pipe --role client --topic <word> [--burn N] [--hold S] [--ping-every E]
module app;

import core.time : MonoTime, msecs, seconds;
import std.conv : to;
import std.getopt : getopt;
import std.stdio : writeln, stdout;
import std.string : indexOf;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

import hyperswarm.cenc : Address;
import hyperswarm.connection : Connection;
import hyperswarm.swarm : Hyperswarm;
import hyperswarm.noise.crypto : keyedBlake2b;

__gshared MonoTime g_t0;
double stamp() { return (MonoTime.currTime - g_t0).total!"msecs" / 1000.0; }

// Server side of the pipe protocol: [8-byte size] + bytes → ack 0x01; PING → PONG.
void serveConn(Connection conn)
{
    ulong got, burnSize;
    conn.onData = (ubyte[] m) nothrow {
        try
        {
            if (m.length >= 4 && cast(string) m[0 .. 4] == "PING") { conn.write(cast(const(ubyte)[]) "PONG"); return; }
            if (burnSize == 0 && m.length >= 8)
            {
                foreach (b; m[0 .. 8]) burnSize = (burnSize << 8) | b;
                m = m[8 .. $];
                writeln("[t+", stamp(), "s] burn of ", burnSize, " bytes announced"); stdout.flush();
            }
            got += m.length;
            if (burnSize && got >= burnSize)
            {
                writeln("[t+", stamp(), "s] burn complete: ", got, " bytes — acking"); stdout.flush();
                conn.write([cast(ubyte) 1]);
                burnSize = 0; got = 0;
            }
        }
        catch (Exception) {}
    };
    conn.onClose = () nothrow { try { writeln("[t+", stamp(), "s] connection closed"); stdout.flush(); } catch (Exception) {} };
}

int main(string[] args)
{
    string role = "server", topicWord = "hs-pipe-test"; uint seed; ulong burnBytes; uint holdSecs, pingEvery = 10;
    string[] bootstrap;
    bool exitOnClose; // server: shut the whole swarm down from the first connection's onClose
    bool destroyClose; // client: end with conn.destroy() whose onClose closes the swarm
    bool abortBurn;    // client: queue the whole burn, then close the swarm without waiting
    bool closeYield;   // with --destroy-close: onClose sleeps 50 ms after closing the swarm
    bool closeOnDiscover; // client: close the swarm from onDiscover, mid-lookup; exit 0 iff it settles
    auto help = getopt(args, "role", &role, "topic", &topicWord, "seed", &seed, "burn", &burnBytes,
        "hold", &holdSecs, "ping-every", &pingEvery, "bootstrap", &bootstrap, "exit-on-close", &exitOnClose, "destroy-close", &destroyClose, "close-yield", &closeYield, "abort", &abortBurn, "close-on-discover", &closeOnDiscover);
    if (help.helpWanted)
    {
        writeln("hs-pipe --role server|client --topic <word> [--burn N] [--hold S] [--ping-every E]");
        return 2;
    }
    if (seed == 0)
        seed = role == "server" ? 17 : 18;
    if (bootstrap.length == 0)
        bootstrap = ["node1.hyperdht.org:49737", "node2.hyperdht.org:49737", "node3.hyperdht.org:49737"];
    Address[] seeds;
    foreach (b; bootstrap)
    {
        immutable k = b.indexOf(':');
        if (k > 0) seeds ~= Address(b[0 .. k].idup, 4, b[k + 1 .. $].to!ushort);
    }
    ubyte[32] topic;
    keyedBlake2b(topic[], cast(const(ubyte)[])("hs-pipe:" ~ topicWord), null);
    g_t0 = MonoTime.currTime;
    int result = 1;
    runTask(() nothrow {
        Hyperswarm swarm;
        try
        {
            ubyte[32] sb = cast(ubyte) seed;
            swarm = new Hyperswarm(seeds, sb[]);
            writeln("[t+", stamp(), "s] hyperswarm on :", swarm.dht.rpc.localPort, " (", role, "), topic ", topicWord); stdout.flush();
            Connection got;
            immutable client = role == "client";
            // A server serves EVERY connection the moment it arrives: a single `got`
            // slot polled every 100 ms let concurrent arrivals overwrite each other.
            swarm.onConnection = (Connection c) nothrow {
                if (client) { got = c; return; }
                try { writeln("[t+", stamp(), "s] OPEN: connection from the topic"); stdout.flush(); } catch (Exception) {}
                try serveConn(c); catch (Exception) {}
                if (exitOnClose)
                    // onClose runs on the UDP reader fiber, inside libudx's stream close:
                    // closing the swarm from here is the shutdown-from-a-callback case.
                    c.onClose = () nothrow {
                        try { writeln("[t+", stamp(), "s] peer closed — closing the swarm from onClose"); stdout.flush(); } catch (Exception) {}
                        try swarm.close(); catch (Exception) {}
                        // From this fiber the close only STARTS: leave the event loop once
                        // it has settled (on another fiber — this one must return first).
                        try runTask(() nothrow {
                            try while (!swarm.closeSettled()) sleep(5.msecs); catch (Exception) {}
                            try exitEventLoop(); catch (Exception) {}
                        }); catch (Exception) {}
                    };
            };
            if (client && closeOnDiscover)
                // onDiscover fires on a DHT request child of discoverLoop, whose query waits
                // for that child: a close() that joined discoverLoop from here deadlocked.
                swarm.onDiscover = (ubyte[32] pk) nothrow {
                    try { writeln("[t+", stamp(), "s] discovered a peer — closing the swarm from onDiscover"); stdout.flush(); } catch (Exception) {}
                    try swarm.close(); catch (Exception) {}
                    try runTask(() nothrow {
                        try
                        {
                            immutable until = MonoTime.currTime + 15.seconds;
                            while (!swarm.closeSettled() && MonoTime.currTime < until)
                                sleep(5.msecs);
                            immutable ok = swarm.closeSettled();
                            writeln("[t+", stamp(), "s] close from onDiscover: settled=", ok,
                                " leftovers=", swarm.dht.rpc.closeLeftovers()); stdout.flush();
                            result = ok ? 0 : 1;
                        }
                        catch (Exception) {}
                        try exitEventLoop(); catch (Exception) {}
                    }); catch (Exception) {}
                };
            swarm.join(topic, /*client*/ client, /*serverMode*/ !client);
            writeln("[t+", stamp(), "s] joined (", client ? "client: lookup + connect" : "server: announced + listening", ")"); stdout.flush();
            if (!client)
            {
                result = 0;
                for (;;)
                    sleep(1.seconds);
            }
            immutable deadline = MonoTime.currTime + 90.seconds;
            while (got is null && MonoTime.currTime < deadline)
                sleep(50.msecs);
            if (got is null)
            {
                throw new Exception("FAIL: no connection from the topic within 90 s");
            }
            auto conn = got;
            writeln("[t+", stamp(), "s] OPEN: connected via the topic (udx + noise secret-stream)"); stdout.flush();
            result = 0;
            bool closed, acked; ubyte[] inbox;
            conn.onClose = () nothrow { closed = true; };
            conn.onData = (ubyte[] m) nothrow {
                if (m.length && m[0] == 1) acked = true;
                else if (m.length >= 4 && cast(string) m[0 .. 4] == "PONG") inbox ~= m;
            };
                if (abortBurn && burnBytes)
                {
                    // Backpressured shutdown: queue everything, then tear down at once —
                    // sends blocked on a full socket, a stream still on it (EBUSY).
                    ubyte[64 * 1024] ab = 0x42;
                    for (ulong q; q < burnBytes; q += ab.length)
                        conn.write(ab[]);
                    writeln("[t+", stamp(), "s] ABORT: ", conn.pendingWrites, " writes pending — closing the swarm now"); stdout.flush();
                    burnBytes = 0; holdSecs = 0;
                }
                if (burnBytes)
                {
                    immutable tb = MonoTime.currTime;
                    ubyte[8] hdr;
                    foreach (i; 0 .. 8) hdr[i] = cast(ubyte)(burnBytes >> (56 - 8 * i));
                    conn.write(hdr[]);
                    ubyte[64 * 1024] buf = 0x42;
                    ulong sent;
                    immutable stallDeadline = MonoTime.currTime + 120.seconds;
                    while (sent < burnBytes && !closed && MonoTime.currTime < stallDeadline)
                    {
                        immutable n = burnBytes - sent < buf.length ? cast(size_t)(burnBytes - sent) : buf.length;
                        conn.write(buf[0 .. n]);
                        sent += n;
                        while (conn.pendingWrites > 64 && !closed && MonoTime.currTime < stallDeadline)
                            sleep(2.msecs);
                    }
                    immutable ackDeadline = MonoTime.currTime + 120.seconds;
                    while (!acked && !closed && MonoTime.currTime < ackDeadline)
                        sleep(20.msecs);
                    if (acked)
                        writeln("[t+", stamp(), "s] BURN PASS: ", burnBytes, " bytes acked in ", (MonoTime.currTime - tb).total!"msecs", " ms");
                    else { writeln("[t+", stamp(), "s] BURN FAIL after ", sent, " bytes (closed=", closed, ")"); result = 1; }
                    stdout.flush();
                }
                if (holdSecs)
                {
                    writeln("HOLD: ", holdSecs, "s, ping every ", pingEvery, "s"); stdout.flush();
                    immutable end = MonoTime.currTime + holdSecs.seconds;
                    bool ok = true;
                    while (true)
                    {
                        immutable next = MonoTime.currTime + pingEvery.seconds;
                        while (MonoTime.currTime < next && MonoTime.currTime < end && !closed)
                            sleep(50.msecs);
                        inbox = null;
                        immutable tp = MonoTime.currTime;
                        conn.write(cast(const(ubyte)[]) "PING");
                        while (inbox.length == 0 && !closed && MonoTime.currTime < tp + 5.seconds)
                            sleep(5.msecs);
                        if (inbox.length == 0) { writeln("[t+", stamp(), "s] PING FAILED (closed=", closed, ")"); ok = false; break; }
                        writeln("[t+", stamp(), "s] ping ok, rtt ", (MonoTime.currTime - tp).total!"usecs" / 1000.0, " ms"); stdout.flush();
                        if (MonoTime.currTime >= end) break;
                    }
                    writeln(ok ? "HOLD PASS: the pipe stayed usable for the whole hold" : "HOLD FAIL"); stdout.flush();
                    if (!ok) result = 1;
                }
                if (destroyClose)
                {
                    // Local destroy: udx may call onClose synchronously on THIS task, and
                    // onClose closes the whole swarm from inside that callback.
                    conn.onClose = () nothrow {
                        try { writeln("[t+", stamp(), "s] onClose after destroy — closing the swarm from it"); stdout.flush(); } catch (Exception) {}
                        try swarm.close(); catch (Exception) {}
                        if (closeYield) // a callback that yields after starting the shutdown
                            try sleep(50.msecs); catch (Exception) {}
                    };
                    conn.destroy();
                }
                else if (!abortBurn)
                    conn.closeGracefully(5.seconds);
        }
        catch (Exception e)
        {
            result = 1;
            try writeln("hs-pipe failed: ", e.msg); catch (Exception) {}
        }
        // Tear the swarm down (dht socket, pool sockets, their reader fibers) before
        // leaving the loop, so a clean exit leaves no live handle behind.
        if (swarm !is null)
        {
            try swarm.close(); catch (Exception) {}
            // A close begun inside a callback settles on its own task: wait for it.
            try
            {
                immutable until = MonoTime.currTime + 10.seconds;
                while (!swarm.closeSettled() && MonoTime.currTime < until)
                    sleep(5.msecs);
                writeln("[t+", stamp(), "s] closed: settled=", swarm.closeSettled(),
                    " leftovers=", swarm.dht.rpc.closeLeftovers()); stdout.flush();
            }
            catch (Exception) {}
        }
        try exitEventLoop(); catch (Exception) {}
    });
    runEventLoop();
    return result;
}
