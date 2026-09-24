/// NAT-type sampler — a verbatim port of hyperdht/lib/nat.js. Feed it the {to,
/// from} of DHT PING replies sent from ONE socket: `to` is our external mapping
/// as that responder saw us, `from` is the responder. From >=3-4 samples it
/// classifies the socket's NAT:
///   OPEN       — reachable, no punch needed.
///   CONSISTENT — endpoint-independent mapping (same external host+port to every
///                responder): punchable by a round-synchronised probe.
///   RANDOM     — symmetric (a fresh mapping per destination): needs the
///                birthday spray (256 sockets) from the far side.
/// The classification drives which strategy connect.d picks, so the thresholds
/// are interop-fragile and kept exactly: minSamples 4, decide at sampled>=3,
/// top host+port hit-count thresholds 3 -> CONSISTENT, 1 -> RANDOM, 2 -> the
/// tie-break below.
module hyperswarm.dht.nat;

import std.format : format;

import hyperswarm.cenc : Address;
import hyperswarm.dht.connect_messages : FW_UNKNOWN, FW_OPEN, FW_CONSISTENT, FW_RANDOM;

private struct Sample
{
    string host;
    ushort port;
    uint hits;
}

final class Nat
{
    private Sample[] samplesHost; // keyed on host only (port forced to 0)
    private Sample[] samplesFull; // keyed on host+port
    private bool[string] visited; // responders already counted (host:port)
    private bool firewalled;
    private bool frozen;

    size_t sampled;
    uint firewall;
    Address[] addresses;

    enum size_t minSamples = 4;

    /// `firewalled` = we have no confirmed reachable address yet (so we might be
    /// behind a NAT). Not firewalled ⇒ OPEN immediately.
    this(bool firewalled)
    {
        this.firewalled = firewalled;
        firewall = firewalled ? FW_UNKNOWN : FW_OPEN;
    }

    /// A responder answered: `to` is our external address it observed, `from` is
    /// the responder. Deduped by responder so one node's retries count once.
    void add(Address to, Address from)
    {
        immutable key = format("%s:%d", from.host, from.port);
        if (key in visited)
            return;
        visited[key] = true;

        addSample(samplesHost, to.host, 0);
        addSample(samplesFull, to.host, to.port);

        ++sampled;
        if ((sampled >= 3 || !firewalled) && !frozen)
            update();
    }

    /// Enough samples to act on (nat.js's resolve condition).
    bool analyzed() const @safe pure nothrow
    {
        return firewall == FW_CONSISTENT || firewall == FW_OPEN || sampled >= minSamples;
    }

    /// Freeze the classification before the punch commits.
    void freeze() @safe pure nothrow
    {
        frozen = true;
    }

    private void update()
    {
        updateFirewall();
        updateAddresses();
    }

    private void updateFirewall()
    {
        if (!firewalled)
        {
            firewall = FW_OPEN;
            return;
        }
        if (sampled < 3)
            return;

        immutable max = samplesFull[0].hits;

        if (max >= 3)
        {
            firewall = FW_CONSISTENT;
            return;
        }
        if (max == 1)
        {
            firewall = FW_RANDOM;
            return;
        }
        // max == 2
        // one host but >= 4 samples (so 2 landed elsewhere) -> random
        if (samplesHost.length == 1 && sampled > 3)
        {
            firewall = FW_RANDOM;
            return;
        }
        // a double-hit on two different hosts -> assume consistent
        if (samplesHost.length > 1 && samplesFull[1].hits > 1)
        {
            firewall = FW_CONSISTENT;
            return;
        }
        // no decision at the expected sample count -> assume random
        if (sampled > 4)
            firewall = FW_RANDOM;
    }

    private void updateAddresses()
    {
        if (firewall == FW_UNKNOWN)
        {
            addresses = null;
            return;
        }
        if (firewall == FW_RANDOM)
        {
            addresses = [Address(samplesHost[0].host, 4, 0)]; // host only
            return;
        }
        if (firewall == FW_CONSISTENT)
        {
            addresses = [];
            foreach (s; samplesFull)
                if (s.hits >= 2 || addresses.length < 2)
                    addresses ~= Address(s.host, 4, s.port);
        }
    }

    // Bump a sample's hit count (or add it), keeping the list sorted descending by
    // hits so [0] is always the most-observed mapping.
    private static void addSample(ref Sample[] samples, string host, ushort port)
    {
        foreach (i; 0 .. samples.length)
        {
            if (samples[i].port != port || samples[i].host != host)
                continue;
            samples[i].hits++;
            for (auto j = i; j > 0; j--)
            {
                if (samples[j - 1].hits >= samples[j].hits)
                    return;
                auto prev = samples[j - 1];
                samples[j - 1] = samples[j];
                samples[j] = prev;
            }
            return;
        }
        samples ~= Sample(host, port, 1);
    }
}

import core.time : Duration, seconds;

import hyperswarm.dht.rpc : Rpc;
import hyperswarm.dht.socket_pool : SocketPool;
import hyperswarm.dht.wire : FIND_NODE;

/// Classify a fresh pool socket's NAT by PINGing DHT nodes FROM it (so the
/// replies' `to` field is that socket's own external mapping). Walks outward:
/// `seeds` (bootstrap nodes) start it, each reply's closerNodes extend it, until
/// the sampler has enough (minSamples) or the reachable nodes run out. The socket
/// is released on the way out; the returned Nat holds the verdict + addresses.
Nat sampleNat(Rpc rpc, SocketPool pool, Address[] seeds, bool firewalled,
    size_t maxPings = Nat.minSamples, Duration timeout = 2.seconds)
{
    auto sock = pool.acquire();
    scope (exit)
        pool.release(sock);
    return sampleNatOn(rpc, sock, seeds, firewalled, maxPings, timeout);
}

/// Same walk as sampleNat, but on a socket the caller already holds (and keeps).
/// The holepuncher uses this to learn its *holder* socket's external mapping — the
/// exact host:port the peer must aim its beacons at — without swapping sockets.
Nat sampleNatOn(Rpc rpc, void* sock, Address[] seeds, bool firewalled,
    size_t maxPings = Nat.minSamples, Duration timeout = 2.seconds)
{
    auto nat = new Nat(firewalled);
    sampleNatInto(nat, rpc, sock, seeds, maxPings, timeout);
    return nat;
}

/// The walk of sampleNatOn feeding an EXISTING Nat, sample by sample: the caller
/// (the holepuncher) reads the verdict from the same object the walk fills, so a
/// round that runs while the walk is still going sees what has been learnt so far
/// rather than a stale object swapped in at the end. Cancellation-aware: an
/// interrupt of the calling task cancels every ping still in flight and joins it
/// before rethrowing, and the normal return joins too — no fiber of this walk
/// outlives the call, so the socket can be released right after.
void sampleNatInto(Nat nat, Rpc rpc, void* sock, Address[] seeds,
    size_t maxPings = Nat.minSamples, Duration timeout = 2.seconds, Duration budget = Duration.max)
{
    import std.random : uniform;
    import vibe.core.core : Task;
    import core.time : MonoTime, msecs;
    immutable deadline = budget == Duration.max ? MonoTime.max : MonoTime.currTime + budget;

    // FIND_NODE toward a fixed random target: its reply carries our observed `to`
    // (the NAT sample, independent of the command) AND closerNodes to walk, so the
    // sample self-bootstraps instead of assuming a populated routing table.
    ubyte[32] target;
    foreach (ref b; target)
        b = cast(ubyte) uniform(0, 256);

    // The pings go out in waves, all of a wave at once: the sample is bound by one
    // round trip per wave, not by the sum of them (and of the timeouts of the nodes
    // that never answer). Serial, this took 1.5 s of the time to connect.
    import vibe.core.core : runTask;
    import vibe.core.sync : createManualEvent;
    Address[] queue = seeds.dup;
    bool[string] pinged;
    size_t sent, inFlight;
    auto changed = createManualEvent();
    Task[] tasks; // every ping launched, so they can be cancelled and joined
    // Cancel what is still in flight and wait for it: a ping parked in its reply
    // wait throws out on interrupt, drops its pending entry and signals `changed`.
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
                // interrupted while joining: keep joining — the children are already
                // cancelled and finish on their own
            }
        }
    }
    scope (exit)
        settle(); // the normal return and an interrupt both leave nothing running
    while (queue.length > 0 && sent < maxPings && !nat.analyzed && MonoTime.currTime < deadline)
    {
        Address[] wave;
        while (queue.length > 0 && wave.length + sent < maxPings)
        {
            immutable node = queue[0];
            queue = queue[1 .. $];
            immutable key = format("%s:%d", node.host, node.port);
            if (key in pinged)
                continue;
            pinged[key] = true;
            wave ~= node;
        }
        if (wave.length == 0)
            break;
        Address[] closer;
        foreach (node; wave)
        {
            inFlight++;
            try
            tasks ~= runTask((Address n) nothrow {
                scope (exit)
                    inFlight--;
                scope (exit)
                    changed.emit();
                try
                {
                    // Cap each request by what remains of the overall budget, so a
                    // wave launched just under the deadline cannot run a whole extra
                    // timeout past it (the server samples under the client's deadline).
                    auto reqTimeout = timeout;
                    if (deadline != MonoTime.max)
                    {
                        auto rem = deadline - MonoTime.currTime;
                        reqTimeout = rem < timeout ? (rem < 1.msecs ? 1.msecs : rem) : timeout;
                    }
                    auto reply = rpc.request(n, FIND_NODE, target[], null, null, true, reqTimeout, sock);
                    nat.add(reply.to, n); // reply.to = our external as this node saw us
                    sent++;
                    closer ~= reply.closerNodes;
                }
                catch (Exception)
                {
                } // unreachable node — the others of the wave still count
            }, node);
            catch (Exception)
                inFlight--; // the child never started: do not wait for it
        }
        while (inFlight > 0 && !nat.analyzed)
        {
            auto ec = changed.emitCount;
            changed.wait(ec); // an interrupt propagates: scope(exit) settles the wave
        }
        queue ~= closer;
    }
}
