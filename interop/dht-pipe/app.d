/// The hyperdht rendezvous end to end, on the PUBLIC hyperdht network, held to the
/// pipe yardstick (burn + hold): a server listens on a key pair (announce under
/// BLAKE2b(publicKey)); a client finds it through the DHT, runs the peer handshake
/// through a relay node and — both being behind NATs — the PEER_HOLEPUNCH rounds,
/// then a udx stream + Noise secret-stream over the hole. Wire-compatible with
/// hyperdht 6.x: either side may be the reference JS peer (pub-server.js /
/// pub-client.js next to this).
///
///   dht-pipe --role server --seed <n>                # prints the public key
///   dht-pipe --role client --key <hex> [--burn N] [--hold S] [--ping-every E]
module app;

import core.time : MonoTime, msecs, seconds;
import core.sys.posix.sys.socket : sockaddr, AF_INET;
import core.sys.posix.netinet.in_ : sockaddr_in;
import core.sys.posix.arpa.inet : htons, inet_addr;
import std.conv : to;
import std.getopt : getopt;
import std.random : uniform;
import std.stdio : writeln, stdout;
import std.string : indexOf, toStringz;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

import hyperswarm.cenc : Address;
import hyperswarm.connection : Connection, hsConnRead, hsConnClose, hsConnFinalize;
import hyperswarm.dht.node : Dht;
import hyperswarm.dht.serve : Server;
import hyperswarm.dht.connect : connectHandshake, connectViaHolepunch, PunchOutcome;
import hyperswarm.noise.crypto : ed25519Keypair, Keypair;
import hyperswarm.noise.stream : SecretStream;
import hyperswarm.udx.udx;

__gshared MonoTime g_t0;
double stamp() { return (MonoTime.currTime - g_t0).total!"msecs" / 1000.0; }

string hex(scope const(ubyte)[] b)
{
    import std.format : format;
    string s;
    foreach (x; b) s ~= format("%02x", x);
    return s;
}
ubyte[32] unhex(string h)
{
    ubyte[32] out_;
    foreach (i; 0 .. 32) out_[i] = cast(ubyte) h[2 * i .. 2 * i + 2].to!int(16);
    return out_;
}

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
    string role = "server", keyHex; uint seed = 0; ulong burnBytes; uint holdSecs, pingEvery = 10;
    string[] bootstrap;
    auto help = getopt(args, "role", &role, "key", &keyHex, "seed", &seed, "burn", &burnBytes,
        "hold", &holdSecs, "ping-every", &pingEvery, "bootstrap", &bootstrap);
    if (help.helpWanted || (role == "client" && keyHex.length != 64))
    {
        writeln("dht-pipe --role server --seed N | --role client --key <hex> [--burn N] [--hold S] [--ping-every E]");
        return 2;
    }
    if (seed == 0)
        seed = role == "server" ? 7 : 8; // distinct identities by default
    if (bootstrap.length == 0)
        bootstrap = ["node1.hyperdht.org:49737", "node2.hyperdht.org:49737", "node3.hyperdht.org:49737"];
    Address[] seeds;
    foreach (b; bootstrap)
    {
        immutable k = b.indexOf(':');
        if (k > 0) seeds ~= Address(b[0 .. k].idup, 4, b[k + 1 .. $].to!ushort);
    }
    g_t0 = MonoTime.currTime;
    int result = 1;
    runTask(() nothrow {
        try
        {
            ubyte[32] sb = cast(ubyte) seed;
            auto kp = ed25519Keypair(sb[]);
            auto dht = new Dht(seeds);
            writeln("[t+", stamp(), "s] dht socket on :", dht.rpc.localPort, ", my key ", hex(kp.publicKey[])); stdout.flush();
            if (role == "server")
            {
                auto server = new Server(dht, kp);
                server.onConnection = (Connection c) nothrow {
                    try { writeln("[t+", stamp(), "s] OPEN: connection from ", hex(c.remotePublicKey[])[0 .. 16], "…"); stdout.flush(); serveConn(c); }
                    catch (Exception) {}
                };
                immutable n = server.listen();
                writeln("[t+", stamp(), "s] LISTENING: announced on ", n, " nodes; key ", hex(kp.publicKey[])); stdout.flush();
                result = 0;
                // Keep the announce fresh (the record and the relays' router entries age out).
                foreach (_; 0 .. 40)
                {
                    sleep(30.seconds);
                    try server.listen(); catch (Exception) {}
                }
            }
            else
            {
                auto key = unhex(keyHex);
                auto our = dht.rpc.remoteAddress();
                if (!our.host.length) our = Address("127.0.0.1", 4, dht.rpc.localPort);
                immutable udxId = cast(uint) uniform(1, uint.max);
                Connection conn;
                writeln("[t+", stamp(), "s] connecting to ", keyHex[0 .. 16], "… (holepunch first)"); stdout.flush();
                auto pr = connectViaHolepunch(dht, key, kp, our, udxId);
                if (pr.outcome == PunchOutcome.failed)
                    throw new Exception("holepunch failed");
                conn = pr.conn;
                if (conn is null)
                {
                    writeln("[t+", stamp(), "s] server offered no holepunch; dialing it directly"); stdout.flush();
                    auto ch = pr.handshake;
                    auto stream = new ubyte[](hs_udx_sizeof_stream());
                    hs_udx_stream_init(dht.rpc.udxPtr, stream.ptr, udxId, &hsConnClose, &hsConnFinalize);
                    hs_udx_stream_read_start(stream.ptr, &hsConnRead);
                    auto ss = SecretStream.fromHandshake(true, ch.hs.tx, ch.hs.rx, ch.hs.hash, ch.hs.remotePublicKey);
                    conn = new Connection(dht.rpc.udxPtr, stream.ptr, ss, ch.hs.remotePublicKey);
                    auto target = ch.serverPayload.addresses4.length ? ch.serverPayload.addresses4[0] : ch.serverAddress;
                    sockaddr_in peer;
                    peer.sin_family = AF_INET;
                    peer.sin_addr.s_addr = inet_addr(target.host.toStringz);
                    peer.sin_port = htons(target.port);
                    hs_udx_stream_connect(stream.ptr, dht.rpc.sockPtr, ch.serverPayload.udx.id, cast(sockaddr*)&peer);
                    conn.start();
                }
                bool closed, acked; ubyte[] inbox;
                conn.onClose = () nothrow { closed = true; };
                conn.onData = (ubyte[] m) nothrow {
                    if (m.length && m[0] == 1) acked = true;
                    else if (m.length >= 4 && cast(string) m[0 .. 4] == "PONG") inbox ~= m;
                };
                immutable openDeadline = MonoTime.currTime + 20.seconds;
                while (!conn.opened && !closed && MonoTime.currTime < openDeadline)
                    sleep(20.msecs);
                if (!conn.opened)
                {
                    writeln("[t+", stamp(), "s] FAIL: secret-stream did not open"); stdout.flush();
                    exitEventLoop(); return;
                }
                writeln("[t+", stamp(), "s] OPEN: udx + noise secret-stream up (via the DHT rendezvous)"); stdout.flush();
                result = 0;
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
                conn.closeGracefully(5.seconds);
            }
        }
        catch (Exception e)
        {
            try writeln("dht-pipe failed: ", e.msg); catch (Exception) {}
        }
        try exitEventLoop(); catch (Exception) {}
    });
    runEventLoop();
    return result;
}
