/// A minimal DHT node: bootstrap + an iterative Kademlia query, and the hyperdht
/// discovery operations built on it — findNode (routing), lookup(topic) and
/// announce(topic). The FIND_NODE / LOOKUP / ANNOUNCE wire is byte-exact; the query
/// is an algorithm over it (the network's replies decide the result), so it
/// interoperates with the real DHT.
module hyperswarm.dht.node;

import hyperswarm.dht.rpc : Rpc;
import hyperswarm.dht.socket_pool : SocketPool;
import hyperswarm.dht.holepuncher : RandomPunchGate;
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
    private SocketPool _pool; // lazily created; the holepuncher's short-lived sockets
    /// The DHT-wide random-punch throttle every holepuncher of this node shares.
    RandomPunchGate randomPunchGate;

    this(Address[] bootstrap, ushort bindPort = 0)
    {
        import std.random : uniform;

        this.rpc = new Rpc(bindPort);
        foreach (ref b; id)
            b = cast(ubyte) uniform(0, 256);
        this.table = new RoutingTable(id);
        this.bootstrap = bootstrap;
        this.randomPunchGate = new RandomPunchGate();
    }

    /// The pool of short-lived udx sockets the holepuncher punches from (hyperdht's
    /// dht._socketPool). Created on first use so a plain DHT node pays nothing for it.
    SocketPool pool()
    {
        if (_pool is null)
            _pool = new SocketPool(rpc);
        return _pool;
    }

    void close()
    {
        if (_pool !is null)
        {
            _pool.closeAll();
            // a pool socket still carrying a stream (UV_EBUSY) closes on a later retry
            auto pool = _pool;
            rpc.onCloseRetry = () nothrow { pool.closeAll(); return pool.openCount() == 0; };
        }
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

    /// A node our last announce landed on, with our address as that node saw us —
    /// hyperdht's announcer.relays: the (relayAddress, peerAddress) pairs a server
    /// hands a firewalled client so its PEER_HOLEPUNCH rounds reach us through a
    /// node that already knows our mapping.
    struct AnnounceRelay
    {
        Address relay;
        Address observed;
    }

    /// Set by announce(): the nodes that accepted it, closest first.
    AnnounceRelay[] announceRelays;

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
        bool internal, int k, Duration per, void delegate(QReply) nothrow onReply = null)
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

        // Kademlia-style parallel walk: up to `alpha` requests in flight toward the
        // closest unqueried nodes; a reply's closerNodes join the pool; stop when
        // every unqueried node is farther than the k-th responder and nothing is
        // in flight. Serial with 2-3 s timeouts on the nodes that never answer, a
        // public-DHT walk took 6-13 s; the punch after it takes 2.
        import vibe.core.task : InterruptException;
import vibe.core.core : runTask;
        import vibe.core.sync : createManualEvent;
        enum alpha = 3;
        enum maxQueried = 80;
        size_t inFlight, launched;
        auto changed = createManualEvent();
        import vibe.core.core : Task;
        Task[] tasks;
        // An interrupt of the walk (a caller giving up) cancels the α requests in
        // flight and joins them: no child outlives the walk.
        void settle() nothrow
        {
            foreach (t; tasks)
                if (t.running)
                    try
                        t.interrupt();
                    catch (Exception)
                    {
                    }
            while (inFlight > 0)
            {
                try
                {
                    auto ec = changed.emitCount;
                    changed.wait(ec);
                }
                catch (Exception)
                {
                }
            }
        }
        scope (exit)
            settle();
        while (true)
        {
            string best;
            foreach (key, ref n; nodes)
            {
                if (key in queried)
                    continue;
                if (best is null || compareDistance(n.id[], nodes[best].id[], target[]) < 0)
                    best = key;
            }
            bool launch = best !is null && launched < maxQueried && inFlight < alpha;
            if (launch)
            {
                auto resp = respondedSorted();
                if (resp.length >= k && compareDistance(nodes[best].id[], resp[k - 1].from.id[], target[]) > 0)
                    launch = false; // nothing closer left to ask
            }
            if (launch)
            {
                queried[best] = true;
                launched++;
                inFlight++;
                auto n = nodes[best];
                auto key = best;
                try
                tasks ~= runTask((Node n, string key) nothrow {
                    scope (exit)
                        inFlight--;
                    scope (exit)
                        changed.emit(); // nothrow: wakes the walk whatever happened here
                    Reply rep;
                    try
                        rep = rpc.request(Address(n.host, 4, n.port), command, target[], value, null, internal, per);
                    catch (InterruptException)
                        return;   // the walk was cancelled: says nothing about the node
                    catch (Exception)
                    {
                        // gone (or not answering): out of the table, so its slot takes a live
                        // node. A full bucket keeps what it has, and nothing else ever evicted —
                        // after hours of uptime the table was mostly nodes that had left, and
                        // every walk and announce started from them.
                        try
                            table.remove(n.id[]);
                        catch (Exception)
                        {
                        }
                        return;
                    }
                    try
                    {
                        table.add(n);
                        // use the node's self-reported id (what it signs/verifies announces
                        // against) when present, else the id derived from its address.
                        if (rep.id.length == 32)
                            n.id[] = rep.id[];
                        replies[key] = QReply(n, rep.token, rep.value);
                        if (onReply !is null)
                            onReply(replies[key]); // streamed: a caller may act before the walk ends
                        foreach (cn; rep.closerNodes)
                        {
                            Node m;
                            m.id = nodeId(cn.host, cn.port);
                            m.host = cn.host;
                            m.port = cn.port;
                            add(m);
                        }
                    }
                    catch (Exception)
                    {
                    }
                }, n, key);
                catch (Exception)
                {
                    inFlight--; // the child never started
                    launched--;
                }
                continue;
            }
            if (inFlight == 0)
                break; // nothing to launch, nothing pending: the walk is over
            auto ec = changed.emitCount;
            changed.wait(ec);
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

    /// Look up the peers announced under `topic`, handing each record to `each` the
    /// moment a node returns it — the walk to the k closest nodes goes on meanwhile.
    /// A client that connects on the first record saves the rest of the walk
    /// (seconds on the public DHT). Duplicates (the same key from several nodes)
    /// are delivered once.
    void lookupEach(ubyte[32] topic, void delegate(PeerRecord) nothrow each, int k = 20,
        Duration per = 2.seconds)
    {
        bool[string] seenPk;
        cast(void) query(topic, HS_LOOKUP, null, false, k, per, (QReply q) nothrow {
            if (q.value.length == 0)
                return;
            try
            {
                auto lr = decodeLookupReply(q.value);
                foreach (p; lr.peers)
                {
                    immutable pk = format("%(%02x%)", p.publicKey[]);
                    if (pk in seenPk)
                        continue;
                    seenPk[pk] = true;
                    each(p);
                }
            }
            catch (Exception)
            {
            }
        });
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
        auto r = announceWith(topic, keyPair, relays, k, per);
        announceRelays = r.relays;
        return r.committed;
    }

    /// The result of one announce: how many nodes stored the record, and which
    /// ones (with the address they observed us at) — the relays a client can route
    /// a handshake through. Per call, so two announce loops interleaving on the
    /// same node never mix or erase each other's sets.
    struct AnnounceResult
    {
        int committed;
        AnnounceRelay[] relays;
    }

    AnnounceResult announceWith(ubyte[32] topic, Keypair keyPair, Address[] relays = [],
        int k = 20, Duration per = 2.seconds)
    {
        AnnounceResult res;
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
                auto r = rpc.request(Address(q.from.host, 4, q.from.port), HS_ANNOUNCE, topic[], val,
                    q.token, false, per);
                if (r.error != 0)
                    continue; // rejected (rate-limited, bad token…): that node holds no route
                res.relays ~= AnnounceRelay(Address(q.from.host, 4, q.from.port), r.to);
                committed++;
            }
            catch (Exception)
            {
            }
        }
        res.committed = committed;
        return res;
    }
}
