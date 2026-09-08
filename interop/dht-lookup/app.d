module app;
import hyperswarm.dht.node : Dht;
import hyperswarm.dht.table : Node;
import hyperswarm.cenc : Address;
import vibe.core.core : runTask, runEventLoop, exitEventLoop;
import std.stdio : writeln;
import std.random : uniform;
import std.algorithm : min;

int main(string[] args)
{
    int result = 1;
    runTask(() nothrow {
        try
        {
            Address[] boot = [
                Address("node1.hyperdht.org", 4, 49737),
                Address("node2.hyperdht.org", 4, 49737),
                Address("node3.hyperdht.org", 4, 49737)
            ];
            auto dht = new Dht(boot);
            ubyte[32] target;
            foreach (ref b; target) b = cast(ubyte) uniform(0, 256);
            auto nodes = dht.findNode(target);
            writeln("D-DHT lookup found ", nodes.length, " nodes (closest first):");
            foreach (n; nodes[0 .. min(5, nodes.length)]) writeln("  ", n.host, ":", n.port);
            if (nodes.length >= 3) { writeln("OK live DHT lookup converged"); result = 0; }
            else writeln("FAIL too few nodes");
            dht.close();
        }
        catch (Exception e) { try writeln("FAIL ", e.msg); catch (Exception) {} }
        try exitEventLoop(); catch (Exception) {}
    });
    runEventLoop();
    return result;
}
