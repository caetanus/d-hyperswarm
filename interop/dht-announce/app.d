/// announce + lookup interop: the D node announces a peer record under a shared
/// topic and then looks the topic up, expecting to find itself. Against a local
/// real hyperdht node (args: <peerPort> <readyFile>) it is deterministic; with no
/// args it runs against the live hyperdht bootstrap nodes.
module app;

import hyperswarm.dht.node : Dht;
import hyperswarm.dht.messages : PeerRecord;
import hyperswarm.noise.crypto : ed25519RandomKeypair;
import hyperswarm.cenc : Address;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import core.time : msecs;
import std.file : readText, exists;
import std.string : strip;
import std.conv : to;
import std.random : uniform;
import std.stdio : writeln;

int main(string[] args)
{
    int result = 1;
    runTask(() nothrow {
        try
        {
            Address[] boot;
            if (args.length >= 3)
            {
                immutable peerPort = args[1].to!ushort;
                immutable readyFile = args[2];
                for (int i = 0; i < 500 && !exists(readyFile); i++)
                    sleep(20.msecs);
                boot = [Address("127.0.0.1", 4, peerPort)];
            }
            else
            {
                boot = [
                    Address("node1.hyperdht.org", 4, 49737),
                    Address("node2.hyperdht.org", 4, 49737),
                    Address("node3.hyperdht.org", 4, 49737)
                ];
            }

            auto dht = new Dht(boot);
            auto kp = ed25519RandomKeypair();
            // shared topic (not BLAKE2b(pubkey), which routes to the connect path)
            ubyte[32] topic;
            foreach (ref t; topic)
                t = cast(ubyte) uniform(0, 256);

            immutable committed = dht.announce(topic, kp);
            writeln("announced to ", committed, " node(s)");
            sleep(500.msecs);

            auto peers = dht.lookup(topic);
            writeln("lookup found ", peers.length, " peer record(s)");
            bool found;
            foreach (p; peers)
                if (p.publicKey == kp.publicKey)
                    found = true;

            if (committed >= 1 && found)
            {
                writeln("OK announce+lookup round-tripped");
                result = 0;
            }
            else
                writeln("FAIL committed=", committed, " found=", found);
            dht.close();
        }
        catch (Exception e) { try writeln("FAIL ", e.msg); catch (Exception) {} }
        try exitEventLoop(); catch (Exception) {}
    });
    runEventLoop();
    return result;
}
