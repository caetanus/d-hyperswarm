/// A minimal DHT node: bootstrap + an iterative Kademlia query, and the hyperdht
/// discovery operations built on it — findNode (routing), lookup(topic) and
/// announce(topic). The FIND_NODE / LOOKUP / ANNOUNCE wire is byte-exact; the query
/// is an algorithm over it (the network's replies decide the result), so it
/// interoperates with the real DHT.
module hyperswarm.dht.node;

import hyperswarm.dht.rpc : Rpc;
import hyperswarm.dht.wire : FIND_NODE, nodeId, Reply;
import hyperswarm.dht.table : RoutingTable, Node, compareDistance;
import hyperswarm.dht.messages : PeerRecord, Announce, encodeAnnounce, signAnnounce,
    decodeLookupReply, HS_LOOKUP, HS_ANNOUNCE;
import hyperswarm.noise.crypto : Keypair;
import hyperswarm.cenc : Address;
import std.algorithm : sort, min;
import std.conv : to;
import std.format : format;
import core.time : Duration, seconds;

final class Dht
{
    Rpc rpc;
    RoutingTable table;
    ubyte[32] id;
    Address[] bootstrap;

    this(Address[] bootstrap, ushort bindPort = 0)
    {
        import std.random : uniform;

        this.rpc = new Rpc(bindPort);
        foreach (ref b; id)
            b = cast(ubyte) uniform(0, 256);
        this.table = new RoutingTable(id);
        this.bootstrap = bootstrap;
    }

    void close()
    {
        rpc.close();
    }

    ushort localPort()
    {
        return rpc.localPort;
    }

    private static string addrKey(Node n)
    {
        return n.host ~ ":" ~ n.port.to!string;
    }

    /// A responded query node with its token and reply value.
    struct QReply
    {
        Node from;
        ubyte[] token;
        ubyte[] value;
    }

    /// Iterative query toward `target` with `command` (internal=true for the
    /// built-in FIND_NODE routing, false for hyperdht LOOKUP/ANNOUNCE). Returns the
    /// responded nodes (with token + value) closest first.
    QReply[] query(ubyte[32] target, uint command, scope const(ubyte)[] value,
        bool internal, int k, Duration per)
    {
        Node[string] nodes;
        bool[string] queried;
        QReply[string] replies;

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

        QReply[] respondedSorted()
        {
            QReply[] r;
            foreach (key, ref q; replies)
                r ~= q;
            sort!((a, b) => compareDistance(a.from.id[], b.from.id[], target[]) < 0)(r);
            return r;
        }

        foreach (_; 0 .. 80)
        {
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

            auto resp = respondedSorted();
            if (resp.length >= k && compareDistance(nodes[best].id[], resp[k - 1].from.id[], target[]) > 0)
                break;

            queried[best] = true;
            auto n = nodes[best];
            Reply rep;
            try
                rep = rpc.request(Address(n.host, 4, n.port), command, target[], value, null, internal, per);
            catch (Exception)
                continue;
            table.add(n);
            // use the node's self-reported id (what it signs/verifies announces
            // against) when present, else the id derived from its address.
            if (rep.id.length == 32)
                n.id[] = rep.id[];
            replies[best] = QReply(n, rep.token, rep.value);
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

    /// Iterative FIND_NODE: the k closest responding nodes to `target`.
    Node[] findNode(ubyte[32] target, int k = 20, Duration per = 2.seconds)
    {
        Node[] outp;
        foreach (q; query(target, FIND_NODE, null, true, k, per))
            outp ~= q.from;
        return outp;
    }

    /// Look up the peers announced under `topic`.
    PeerRecord[] lookup(ubyte[32] topic, int k = 20, Duration per = 2.seconds)
    {
        PeerRecord[] peers;
        bool[string] seenPk;
        foreach (q; query(topic, HS_LOOKUP, null, false, k, per))
        {
            if (q.value.length == 0)
                continue;
            auto lr = decodeLookupReply(q.value);
            foreach (p; lr.peers)
            {
                immutable pk = format("%(%02x%)", p.publicKey[]);
                if (pk !in seenPk)
                {
                    seenPk[pk] = true;
                    peers ~= p;
                }
            }
        }
        return peers;
    }

    /// Announce `keyPair` under `topic`: find the closest nodes (with tokens), then
    /// send each a signed ANNOUNCE. Returns how many nodes accepted the commit.
    int announce(ubyte[32] topic, Keypair keyPair, Address[] relays = [], int k = 20,
        Duration per = 2.seconds)
    {
        int committed;
        foreach (q; query(topic, HS_LOOKUP, null, false, k, per))
        {
            if (q.token.length != 32)
                continue;
            PeerRecord peer;
            peer.publicKey = keyPair.publicKey;
            peer.relayAddresses = relays;
            Announce ann;
            ann.hasPeer = true;
            ann.peer = peer;
            ann.hasSignature = true;
            ann.signature = signAnnounce(topic[], q.token, q.from.id[], peer, keyPair);
            auto val = encodeAnnounce(ann);
            try
            {
                rpc.request(Address(q.from.host, 4, q.from.port), HS_ANNOUNCE, topic[], val,
                    q.token, false, per);
                committed++;
            }
            catch (Exception)
            {
            }
        }
        return committed;
    }
}
