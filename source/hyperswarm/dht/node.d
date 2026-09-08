/// A minimal DHT node: bootstrap + the iterative Kademlia lookup (findNode) that
/// hyperdht's announce/lookup/connect ride on. findNode walks toward a target,
/// querying the closest unqueried nodes with FIND_NODE and folding in the
/// closerNodes each returns, until the k closest have answered.
///
/// The FIND_NODE wire is byte-exact (validated separately); the lookup is an
/// algorithm over it — the network's replies decide the result, not our pacing —
/// so it interoperates with the real DHT.
module hyperswarm.dht.node;

import hyperswarm.dht.rpc : Rpc;
import hyperswarm.dht.wire : FIND_NODE, nodeId, Reply;
import hyperswarm.dht.table : RoutingTable, Node, compareDistance;
import hyperswarm.cenc : Address;
import std.algorithm : sort, min;
import std.conv : to;
import core.time : Duration, seconds, msecs;

final class Dht
{
    Rpc rpc;
    RoutingTable table;
    ubyte[32] id;
    Address[] bootstrap;

    this(Address[] bootstrap, ushort bindPort = 0)
    {
        this.rpc = new Rpc(bindPort);
        // an ephemeral client id; only affects our own bucket layout, not the
        // XOR ordering of a lookup (which is relative to the target).
        import std.random : uniform;

        foreach (ref b; id)
            b = cast(ubyte) uniform(0, 256);
        this.table = new RoutingTable(id);
        this.bootstrap = bootstrap;
    }

    void close()
    {
        rpc.close();
    }

    private static string addrKey(Node n)
    {
        return n.host ~ ":" ~ n.port.to!string;
    }

    /// Iterative FIND_NODE toward `target`; returns up to k responding nodes,
    /// closest first.
    Node[] findNode(ubyte[32] target, int k = 20, Duration perRequest = 2.seconds)
    {
        Node[string] nodes;
        bool[string] queried;
        bool[string] responded;

        void add(Node n)
        {
            immutable key = addrKey(n);
            if (key !in nodes)
                nodes[key] = n;
        }

        foreach (b; bootstrap)
        {
            Node n;
            n.id = nodeId(b.host, b.port);
            n.host = b.host;
            n.port = b.port;
            add(n);
        }
        foreach (n; table.closest(target[], k))
            add(n);

        Node[] respondedSorted()
        {
            Node[] r;
            foreach (key, ref n; nodes)
                if (key in responded)
                    r ~= n;
            sort!((a, b) => compareDistance(a.id[], b.id[], target[]) < 0)(r);
            return r;
        }

        foreach (_; 0 .. 60)
        {
            // closest unqueried node
            string best;
            foreach (key, ref n; nodes)
            {
                if (key in queried)
                    continue;
                if (best is null || compareDistance(n.id[], nodes[best].id[], target[]) < 0)
                    best = key;
            }
            if (best is null)
                break;

            // converged: the closest unqueried is no nearer than the k-th responder
            auto resp = respondedSorted();
            if (resp.length >= k && compareDistance(nodes[best].id[], resp[k - 1].id[], target[]) > 0)
                break;

            queried[best] = true;
            auto n = nodes[best];
            Reply rep;
            try
                rep = rpc.request(Address(n.host, 4, n.port), FIND_NODE, target[], null, perRequest);
            catch (Exception)
                continue; // timed out / unreachable
            responded[best] = true;
            table.add(n);
            foreach (cn; rep.closerNodes)
            {
                Node m;
                m.id = nodeId(cn.host, cn.port);
                m.host = cn.host;
                m.port = cn.port;
                add(m);
            }
        }

        auto result = respondedSorted();
        return result[0 .. min(k, result.length)];
    }
}
