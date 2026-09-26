/// The udx PIPE across two real NATs, rendezvous left out: both NATs on the rig
/// are endpoint-independent and port-preserving, so each side opens its own
/// mapping with a couple of datagrams to the peer's public ip:port and udx then
/// connects straight through the holes. What this measures is the pipe itself —
/// a Noise secret-stream over one udx stream: a bulk burn with an ack, then a
/// hold with pings — the same yardstick the QUIC and TCP pipes were held to.
///
///   udx-pipe --bind-port P --peer <ip:port> --role server
///   udx-pipe --bind-port P --peer <ip:port> --role client --burn 4194304 --hold 60 --ping-every 10
module app;

import core.time : MonoTime, msecs, seconds;
import core.sys.posix.sys.socket : sockaddr, AF_INET;
import core.sys.posix.netinet.in_ : sockaddr_in;
import core.sys.posix.arpa.inet : htons, inet_pton;
import std.conv : to;
import std.getopt : getopt;
import std.algorithm.searching : startsWith;
import std.stdio : writeln, stdout;
import std.string : indexOf, toStringz;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

import hyperswarm.cenc : Address;
import hyperswarm.connection : Connection, hsConnRead, hsConnClose, hsConnFinalize;
import hyperswarm.dht.rpc : Rpc;
import hyperswarm.dht.nat : sampleNatOn;
import std.file : write, readText, exists;
import std.string : strip;
import hyperswarm.noise.crypto : ed25519Keypair;
import hyperswarm.noise.stream : SecretStream;
import hyperswarm.udx.udx;

__gshared MonoTime g_t0;
double stamp() { return (MonoTime.currTime - g_t0).total!"msecs" / 1000.0; }

int main(string[] args)
{
    ushort bindPort; string peerStr, role = "server", outFile, peerFile, goFile, goOut; ulong burnBytes; uint holdSecs, pingEvery = 10;
    string[] bootstrap;
    long fireAt; // --fire-at: unix seconds; both sides send their first datagram at this instant
    auto help = getopt(args, "bind-port", &bindPort, "peer", &peerStr, "role", &role,
        "burn", &burnBytes, "hold", &holdSecs, "ping-every", &pingEvery,
        "out-file", &outFile, "peer-file", &peerFile, "bootstrap", &bootstrap,
        "go-file", &goFile, "go-out", &goOut, "fire-at", &fireAt);
    if (help.helpWanted || bindPort == 0 || (peerStr.indexOf(':') <= 0 && peerFile.length == 0))
    {
        writeln("udx-pipe --bind-port P (--peer ip:port | --peer-file F) [--out-file F] --role server|client [--burn N] [--hold S] [--ping-every E]");
        return 2;
    }
    if (bootstrap.length == 0)
        bootstrap = ["node1.hyperdht.org:49737", "node2.hyperdht.org:49737", "node3.hyperdht.org:49737"];
    immutable client = role == "client";
    g_t0 = MonoTime.currTime;

    int result = 1;
    runTask(() nothrow {
        try
        {
            auto rpc = new Rpc(bindPort);
            writeln("[t+", stamp(), "s] udx socket on :", rpc.localPort, " (", role, ")");
            stdout.flush();

            // Learn THIS socket's external mapping the hyperdht way: FIND_NODE at the
            // bootstrap nodes, each reply echoing the `to` it saw. That is the address
            // the peer must aim at — a NAT need not preserve our port.
            Address[] seeds;
            foreach (b; bootstrap)
            {
                immutable k = b.indexOf(':');
                if (k > 0)
                    seeds ~= Address(b[0 .. k].idup, 4, b[k + 1 .. $].to!ushort);
            }
            auto nat = sampleNatOn(rpc, rpc.sockPtr, seeds, true);
            // a peer on this host (an emulated link in a network namespace): no mapping to learn
            if (nat.addresses.length == 0 && peerStr.startsWith("127."))
                nat.addresses ~= Address("127.0.0.1", 4, rpc.localPort);
            if (nat.addresses.length == 0)
                throw new Exception("could not learn our external mapping (bootstrap unreachable)");
            auto mine = nat.addresses[0];
            writeln("[t+", stamp(), "s] my external mapping: ", mine.host, ":", mine.port, " (firewall ", nat.firewall, ", ", nat.addresses.length, " distinct)");
            stdout.flush();
            if (outFile.length)
                write(outFile, mine.host ~ ":" ~ mine.port.to!string);
            if (peerFile.length)
            {
                writeln("[t+", stamp(), "s] waiting for the peer's mapping in ", peerFile); stdout.flush();
                // The file may exist before it is fully written; wait for a whole ip:port.
                auto lastKeep = MonoTime.currTime;
                do
                {
                    sleep(200.msecs);
                    // Keep our NAT mapping alive meanwhile (a UDP mapping dies in seconds
                    // of silence and its successor need not get the same port).
                    if (MonoTime.currTime - lastKeep > 3.seconds)
                    {
                        rpc.send(seeds[0], [cast(ubyte) 0]);
                        lastKeep = MonoTime.currTime;
                    }
                    try peerStr = exists(peerFile) ? readText(peerFile).strip : ""; catch (Exception) { peerStr = ""; }
                }
                while (peerStr.indexOf(':') <= 0 || peerStr.length < 9);
            }
            immutable c = peerStr.indexOf(':');
            auto peer = Address(peerStr[0 .. c].idup, 4, peerStr[c + 1 .. $].to!ushort);
            writeln("[t+", stamp(), "s] peer mapping: ", peerStr); stdout.flush();
            // Ordering matters behind a conntrack NAT (Docker): a datagram that reaches
            // the host BEFORE the inside peer has sent creates a host-level entry on
            // that port, and the inside peer's later send is then SNATed to a fresh
            // port — the hole misses. So the server punches first (DCUtR does the
            // same: the responder dials at once, the initiator waits): the client
            // sends nothing toward the peer until the go file appears.
            // Or: both fire at one wall-clock instant, so each NAT sees its own outbound
            // before the peer's inbound (a conntrack NAT that sees the inbound first
            // books that tuple and SNATs our later send to a fresh port — the DCUtR
            // rtt/2 dance exists for exactly this). Keepalives keep the mapping alive.
            if (fireAt)
            {
                import std.datetime.systime : Clock;
                writeln("[t+", stamp(), "s] holding until fire-at ", fireAt); stdout.flush();
                auto lastKeep3 = MonoTime.currTime;
                while (Clock.currTime.toUnixTime < fireAt)
                {
                    sleep(20.msecs);
                    if (MonoTime.currTime - lastKeep3 > 3.seconds)
                    {
                        rpc.send(seeds[0], [cast(ubyte) 0]);
                        lastKeep3 = MonoTime.currTime;
                    }
                }
                writeln("[t+", stamp(), "s] FIRE"); stdout.flush();
            }
            if (goFile.length)
            {
                writeln("[t+", stamp(), "s] waiting for go: ", goFile); stdout.flush();
                auto lastKeep2 = MonoTime.currTime;
                while (!exists(goFile))
                {
                    sleep(100.msecs);
                    if (MonoTime.currTime - lastKeep2 > 3.seconds)
                    {
                        rpc.send(seeds[0], [cast(ubyte) 0]);
                        lastKeep2 = MonoTime.currTime;
                    }
                }
            }

            // Open our NAT mapping toward the peer (and keep it warm until udx talks).
            foreach (_; 0 .. 3)
            {
                rpc.send(peer, [cast(ubyte) 0xff, 0xfe, 0xfd]);
                sleep(300.msecs);
            }
            if (goOut.length)
                write(goOut, "go");

            // One udx stream: ids fixed (client 1 <-> server 2), a fresh Noise XX
            // secret-stream on top — no DHT handshake, this is the pipe only.
            ubyte[32] seed = client ? 1 : 2;
            auto kp = ed25519Keypair(seed[]);
            auto ss = new SecretStream(client, kp);
            auto stream = new ubyte[](hs_udx_sizeof_stream());
            hs_udx_stream_init(rpc.udxPtr, stream.ptr, client ? 1 : 2, &hsConnClose, &hsConnFinalize);
            hs_udx_stream_read_start(stream.ptr, &hsConnRead);
            ubyte[32] pk;
            auto conn = new Connection(rpc.udxPtr, stream.ptr, ss, pk);

            bool closed;
            conn.onClose = () nothrow { closed = true; };
            ulong got, burnSize; bool acked; ubyte[] inbox;
            conn.onData = (ubyte[] m) nothrow {
                try
                {
                    if (client)
                    {
                        if (m.length && m[0] == 1) acked = true;   // burn ack
                        else if (m.length >= 4 && cast(string) m[0 .. 4] == "PONG") inbox ~= m;
                        return;
                    }
                    // server: [8-byte size] then bytes; PING -> PONG
                    if (m.length >= 4 && cast(string) m[0 .. 4] == "PING") { conn.write(cast(const(ubyte)[]) "PONG"); return; }
                    if (burnSize == 0 && m.length >= 8)
                    {
                        foreach (b; m[0 .. 8]) burnSize = (burnSize << 8) | b;
                        m = m[8 .. $];
                        writeln("[t+", stamp(), "s] burn of ", burnSize, " bytes announced"); stdout.flush();
                    }
                    got += m.length;
                    if (burnSize && (got / (256 * 1024)) != ((got - m.length) / (256 * 1024)))
                    {
                        writeln("[t+", stamp(), "s] burn progress: ", got, " / ", burnSize); stdout.flush();
                    }
                    if (burnSize && got >= burnSize)
                    {
                        writeln("[t+", stamp(), "s] burn complete: ", got, " bytes — acking"); stdout.flush();
                        conn.write([cast(ubyte) 1]);
                        burnSize = 0; got = 0;
                    }
                }
                catch (Exception) {}
            };

            sockaddr_in sa;
            sa.sin_family = AF_INET;
            sa.sin_port = htons(peer.port);
            inet_pton(AF_INET, peer.host.toStringz, &sa.sin_addr);
            hs_udx_stream_connect(stream.ptr, rpc.sockPtr, client ? 2 : 1, cast(sockaddr*)&sa);
            conn.start();

            immutable openDeadline = MonoTime.currTime + 20.seconds;
            while (!conn.opened && !closed && MonoTime.currTime < openDeadline)
                sleep(20.msecs);
            if (!conn.opened)
            {
                writeln("[t+", stamp(), "s] FAIL: secret-stream did not open over the hole"); stdout.flush();
                exitEventLoop(); return;
            }
            writeln("[t+", stamp(), "s] OPEN: udx + noise secret-stream up through both NATs"); stdout.flush();
            result = 0;

            if (client)
            {
                if (burnBytes)
                {
                    immutable tb = MonoTime.currTime;
                    ubyte[8] hdr;
                    foreach (i; 0 .. 8) hdr[i] = cast(ubyte)(burnBytes >> (56 - 8 * i));
                    conn.write(hdr[]);
                    ubyte[64 * 1024] buf = 0x42;
                    ulong sent;
                    while (sent < burnBytes && !closed)
                    {
                        immutable n = burnBytes - sent < buf.length ? cast(size_t)(burnBytes - sent) : buf.length;
                        conn.write(buf[0 .. n]);
                        sent += n;
                        while (conn.pendingWrites > 64 && !closed)
                            sleep(2.msecs); // udx queues everything; keep the in-flight window bounded
                    }
                    writeln("[t+", stamp(), "s] all ", sent, " bytes handed to udx; pending writes ", conn.pendingWrites); stdout.flush();
                    immutable ackDeadline = MonoTime.currTime + 120.seconds;
                    auto lastP = MonoTime.currTime;
                    while (!acked && !closed && MonoTime.currTime < ackDeadline)
                    {
                        sleep(20.msecs);
                        if (MonoTime.currTime - lastP > 5.seconds)
                        {
                            writeln("[t+", stamp(), "s] waiting for ack; pending writes ", conn.pendingWrites); stdout.flush();
                            lastP = MonoTime.currTime;
                        }
                    }
                    if (acked)
                        writeln("[t+", stamp(), "s] BURN PASS: ", burnBytes, " bytes acked in ", (MonoTime.currTime - tb).total!"msecs", " ms");
                    else
                    {
                        writeln("[t+", stamp(), "s] BURN FAIL after ", sent, " bytes (closed=", closed, ")");
                        result = 1;
                    }
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
                        if (inbox.length == 0)
                        {
                            writeln("[t+", stamp(), "s] PING FAILED (closed=", closed, ")"); ok = false; break;
                        }
                        writeln("[t+", stamp(), "s] ping ok, rtt ", (MonoTime.currTime - tp).total!"usecs" / 1000.0, " ms");
                        stdout.flush();
                        if (MonoTime.currTime >= end) break;
                    }
                    writeln(ok ? "HOLD PASS: the udx pipe stayed usable for the whole hold" : "HOLD FAIL");
                    stdout.flush();
                    if (!ok) result = 1;
                }
                conn.closeGracefully(5.seconds);
            }
            else
            {
                // server: stay until the client closes (or 10 min)
                immutable end = MonoTime.currTime + 600.seconds;
                while (!closed && MonoTime.currTime < end)
                    sleep(100.msecs);
                writeln("[t+", stamp(), "s] connection closed by peer: ", closed); stdout.flush();
            }
        }
        catch (Exception e)
        {
            try writeln("udx-pipe failed: ", e.msg); catch (Exception) {}
        }
        try exitEventLoop(); catch (Exception) {}
    });
    runEventLoop();
    return result;
}
