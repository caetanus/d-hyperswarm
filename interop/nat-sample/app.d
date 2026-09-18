/// Holepunch Stage C live smoke: classify THIS host's NAT against the real
/// hyperdht network. Opens a pool socket, PINGs the bootstrap nodes (and the
/// closerNodes they return) from it, and feeds each reply's observed `to` into
/// the sampler. Prints OPEN / CONSISTENT / RANDOM — compare against a raw
/// multi-STUN natcheck from the same box; they should agree.
///
///   nat-sample [--bootstrap host:port]...   (repeatable; defaults to hyperdht)
module app;

import std.getopt : getopt;
import std.stdio : writeln, stderr, stdout;
import std.string : lastIndexOf;
import std.conv : to;
import core.time : seconds;

import vibe.core.core : runTask, runEventLoop, exitEventLoop;

import hyperswarm.cenc : Address;
import hyperswarm.dht.rpc : Rpc;
import hyperswarm.dht.socket_pool : SocketPool;
import hyperswarm.dht.nat : sampleNat;
import hyperswarm.dht.connect_messages : FW_UNKNOWN, FW_OPEN, FW_CONSISTENT, FW_RANDOM;

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

private enum string[] defaultBootstrap = [
    "node1.hyperdht.org:49737",
    "node2.hyperdht.org:49737",
];

int main(string[] args)
{
    string[] bootstrap;
    auto help = getopt(args, "bootstrap", &bootstrap);
    if (help.helpWanted)
    {
        writeln("nat-sample [--bootstrap host:port]...");
        return 0;
    }
    if (bootstrap.length == 0)
        bootstrap = defaultBootstrap.dup;

    Address[] seeds;
    foreach (b; bootstrap)
    {
        immutable c = b.lastIndexOf(':');
        if (c < 0)
            continue;
        seeds ~= Address(b[0 .. c], 4, b[c + 1 .. $].to!ushort);
    }

    int result = 1;
    runTask(() nothrow {
        try
        {
            auto rpc = new Rpc(0);
            scope (exit)
                rpc.close();
            auto pool = new SocketPool(rpc);
            scope (exit)
                pool.closeAll();

            writeln("sampling NAT against ", seeds.length, " bootstrap seed(s)...");
            auto nat = sampleNat(rpc, pool, seeds, /*firewalled*/ true, 8, 2.seconds);

            writeln("sampled ", nat.sampled, " responder(s) -> ", fwName(nat.firewall));
            foreach (a; nat.addresses)
                writeln("  external: ", a.host, ":", a.port);

            if (nat.firewall != FW_UNKNOWN && nat.sampled >= 3)
            {
                writeln("PASS: NAT classified as ", fwName(nat.firewall));
                result = 0;
            }
            else
                writeln("FAIL: could not classify (bootstrap unreachable / too few samples)");
        }
        catch (Exception e)
        {
            try
                stderr.writeln("nat-sample error: ", e.msg);
            catch (Exception)
            {
            }
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
