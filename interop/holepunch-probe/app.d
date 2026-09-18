/// Holepunch Stage F rig harness: run the real Holepuncher across two real NATs.
/// Each side opens a punch socket, learns its external mapping off the live DHT
/// (sampleNatOn from the holder socket), prints it, and reads the PEER's mapping
/// from stdin — a manual, controlled exchange (no public relay coordinating the
/// two nodes). Then it punches. The initiator reports SUCCESS when an inbound
/// beacon proves the hole opened; the responder reflects and keeps the round
/// alive. This validates the CONSISTENT×CONSISTENT _consistentProbe leg that the
/// loopback unit test can't reproduce.
///
///   holepunch-probe --role initiator|responder [--bootstrap host:port]...
///
/// Run on both machines at once. Each prints "MY MAPPING: host:port"; paste the
/// other's line into each when prompted.
module app;

import std.getopt : getopt;
import std.stdio : writeln, write, stderr, stdout, stdin;
import std.string : lastIndexOf, strip;
import std.conv : to;
import core.time : seconds, msecs;
import core.thread : Thread;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

import hyperswarm.cenc : Address;
import hyperswarm.dht.rpc : Rpc;
import hyperswarm.dht.socket_pool : SocketPool;
import hyperswarm.dht.nat : sampleNatOn;
import hyperswarm.dht.holepuncher : Holepuncher;
import hyperswarm.dht.connect_messages : FW_UNKNOWN, FW_OPEN, FW_CONSISTENT, FW_RANDOM;

private enum string[] defaultBootstrap = [
    "node1.hyperdht.org:49737",
    "node2.hyperdht.org:49737",
];

private string fwName(uint f)
{
    switch (f)
    {
    case FW_OPEN:
        return "OPEN";
    case FW_CONSISTENT:
        return "CONSISTENT";
    case FW_RANDOM:
        return "RANDOM";
    default:
        return "UNKNOWN";
    }
}

private Address parseAddr(string s)
{
    immutable c = s.lastIndexOf(':');
    if (c < 0)
        return Address(null, 4, 0);
    return Address(s[0 .. c], 4, s[c + 1 .. $].strip.to!ushort);
}

// Filled by a blocking stdin reader thread so the vibe loop never parks on I/O.
private __gshared string g_peerLine;
private __gshared bool g_peerReady;

private void readPeerLine() nothrow
{
    try
    {
        auto line = stdin.readln();
        synchronized
        {
            g_peerLine = line is null ? "" : line.idup;
            g_peerReady = true;
        }
    }
    catch (Exception)
    {
        synchronized
        {
            g_peerReady = true;
        }
    }
}

int main(string[] args)
{
    string role = "initiator";
    string[] bootstrap;
    auto help = getopt(args, "role", &role, "bootstrap", &bootstrap);
    if (help.helpWanted)
    {
        writeln("holepunch-probe --role initiator|responder [--bootstrap host:port]...");
        return 0;
    }
    if (bootstrap.length == 0)
        bootstrap = defaultBootstrap.dup;
    immutable isInitiator = role != "responder";

    Address[] seeds;
    foreach (b; bootstrap)
    {
        auto a = parseAddr(b);
        if (a.host !is null)
            seeds ~= a;
    }

    int result = 1;
    runTask(() nothrow {
        Rpc rpc;
        SocketPool pool;
        Holepuncher hp;
        try
        {
            rpc = new Rpc(0);
            pool = new SocketPool(rpc);
            hp = new Holepuncher(rpc, pool, isInitiator, FW_CONSISTENT);

            // 1. Learn the punch socket's own external mapping off the live DHT.
            writeln("[", role, "] sampling holder socket's external mapping...");
            auto nat = sampleNatOn(rpc, hp.socket(), seeds, /*firewalled*/ true, 8, 2.seconds);
            hp.localFirewall = nat.firewall;

            if (nat.addresses.length == 0)
            {
                writeln("[", role, "] FAIL: could not sample an external mapping (bootstrap unreachable?)");
                exitEventLoop();
                return;
            }
            immutable mine = nat.addresses[0];
            writeln("[", role, "] firewall=", fwName(nat.firewall), " (sampled ", nat.sampled, ")");
            writeln("MY MAPPING: ", mine.host, ":", mine.port);
            if (nat.firewall != FW_CONSISTENT && nat.firewall != FW_OPEN)
                writeln("[", role, "] note: this rig leg only exercises the CONSISTENT path; got ",
                    fwName(nat.firewall));

            // 2. Exchange: read the peer's mapping from stdin without parking the loop.
            write("PASTE PEER MAPPING (host:port) THEN ENTER: ");
            stdout.flush();
            new Thread(&readPeerLine).start();
            while (true)
            {
                bool ready;
                synchronized
                    ready = g_peerReady;
                if (ready)
                    break;
                sleep(100.msecs);
            }
            string peerLine;
            synchronized
                peerLine = g_peerLine;
            auto peer = parseAddr(peerLine.strip);
            if (peer.host is null || peer.port == 0)
            {
                writeln("[", role, "] FAIL: bad peer mapping: '", peerLine.strip, "'");
                exitEventLoop();
                return;
            }
            writeln("[", role, "] punching toward ", peer.host, ":", peer.port, " ...");

            // 3. Punch. The exchange was manual+controlled, so the peer addr is trusted.
            bool done;
            hp.onConnect = (void* sock, Address from) nothrow {
                try
                {
                    writeln("[", role, "] SUCCESS: hole open, beacon from ", from.host, ":", from.port);
                }
                catch (Exception)
                {
                }
                result = 0;
                done = true;
            };
            hp.onAbort = () nothrow {
                try
                    writeln("[", role, "] ABORT: punch abandoned");
                catch (Exception)
                {
                }
                done = true;
            };

            hp.updateRemote(true, FW_CONSISTENT, [Address(peer.host, 4, peer.port)], peer.host);
            hp.punch();

            // 4. Run up to ~45s. The responder never self-connects (it reflects), so a
            //    clean reflecting run is its success; the initiator flips result on SUCCESS.
            foreach (_; 0 .. 450)
            {
                if (done)
                    break;
                sleep(100.msecs);
            }
            if (!isInitiator && !done)
            {
                writeln("[", role, "] reflected for the full round (initiator confirms the hole)");
                result = 0;
            }
            hp.destroy();
        }
        catch (Exception e)
        {
            try
                stderr.writeln("[", role, "] error: ", e.msg);
            catch (Exception)
            {
            }
        }
        try
        {
            if (rpc !is null)
                rpc.close();
        }
        catch (Exception)
        {
        }
        try
            stdout.flush();
        catch (Exception)
        {
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
