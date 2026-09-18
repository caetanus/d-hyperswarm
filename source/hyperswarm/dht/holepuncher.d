/// The round-synchronised NAT holepuncher — port of hyperdht/lib/holepuncher.js.
/// Given the two peers' NAT verdicts (from nat.d) and the addresses they exchanged
/// over the DHT (encrypted by secure_payload.d), it fires the 1-byte HOLEPUNCH
/// beacon `[0x00]` on a schedule tuned to open both NATs at once. Three strategies,
/// selected by the (local, remote) firewall pair after coercing OPEN→CONSISTENT:
///
///   CONSISTENT × CONSISTENT — _consistentProbe: a slow (1s) beacon volley at the
///     peer's fixed mapping; endpoint-independent NATs let it straight through.
///   CONSISTENT × RANDOM     — _randomProbes: 1750 beacons at random ports on the
///     peer host (~35s) — we're the guessable side, the peer sprays back.
///   RANDOM × CONSISTENT     — _openBirthdaySockets + _keepAliveRandomNat: open 256
///     sockets (birthday paradox) each beaconing the peer, so one of our random
///     mappings collides with the port the peer is guessing.
///
/// The beacon TTLs are load-bearing: HOLEPUNCH_TTL (5) opens our own NAT without
/// the packet reaching the peer yet (it dies in transit), DEFAULT_TTL (64) is a
/// real probe. Only the INITIATOR "connects" off an inbound beacon; the responder
/// reflects every beacon it gets so the initiator's NAT sees return traffic. The
/// UDX stream over the punched hole is wired on top in connect.d (Stage E).
module hyperswarm.dht.holepuncher;

import core.time : msecs, seconds;
import std.random : uniform;

import vibe.core.core : runTask;

import hyperswarm.cenc : Address;
import hyperswarm.dht.rpc : Rpc;
import hyperswarm.dht.socket_pool : SocketPool;
import hyperswarm.dht.sleeper : Sleeper;
import hyperswarm.dht.connect_messages : FW_UNKNOWN, FW_OPEN, FW_CONSISTENT, FW_RANDOM;

enum size_t BIRTHDAY_SOCKETS = 256;
enum int HOLEPUNCH_TTL = 5;
enum int DEFAULT_TTL = 64;
enum int MAX_REOPENS = 3;

/// One address the peer told us to punch, plus whether we've confirmed traffic
/// from it (a verified address is safe to spray; unverified ones are probed
/// sparingly, every 4th consistent tick).
struct RemoteAddr
{
    string host;
    ushort port;
    bool verified;
}

final class Holepuncher
{
    private Rpc rpc;
    private SocketPool pool;
    private Sleeper sleeper;

    private void*[] holders; // pool sockets we punch from; holders[0] is primary

    bool isInitiator;
    uint localFirewall = FW_UNKNOWN; // set from nat.d's verdict before punch()
    uint remoteFirewall = FW_UNKNOWN;
    RemoteAddr[] remoteAddresses;
    bool remoteHolepunching;

    bool punching;
    bool connected;
    bool destroyed;
    bool randomized;

    /// Fired on the initiator when an inbound beacon proves the hole is open:
    /// (winning socket, peer address the beacon came from).
    void delegate(void* sock, Address from) nothrow onConnect;
    /// Fired when the punch is abandoned without connecting.
    void delegate() nothrow onAbort;

    /// Test seam: when set, every beacon is delivered here instead of hitting the
    /// wire, so the RANDOM/birthday strategies (which no rig can reproduce without a
    /// symmetric NAT) can be asserted without real sends. Null in production.
    void delegate(void* sock, Address to, int ttl) nothrow onBeaconSent;

    /// Diagnostic trace, non-suppressing: fired for every beacon this puncher sends
    /// (sent=true) and receives (sent=false), so a harness can log the punch and
    /// correlate it with a packet capture. `srcPort` is the bound port of the socket
    /// the beacon actually leaves from (0 on receive) — to catch a send going out a
    /// different fd than the sampled holder. Null in production; unlike onBeaconSent
    /// it does NOT replace the real send.
    void delegate(bool sent, Address addr, int ttl, ushort srcPort) nothrow onBeaconTrace;

    // All beacons funnel through here so the test seam sees every send.
    private void beacon(void* sock, Address to, int ttl) nothrow
    {
        if (onBeaconSent !is null)
        {
            onBeaconSent(sock, to, ttl); // suppressing unit-test seam
            return;
        }
        if (onBeaconTrace !is null)
            onBeaconTrace(true, to, ttl, pool.boundPort(sock));
        rpc.sendBeacon(sock, to, ttl);
    }

    /// Sockets currently held (holders.length), for tests asserting the birthday spray.
    size_t holderCount() const nothrow
    {
        return holders.length;
    }

    this(Rpc rpc, SocketPool pool, bool isInitiator, uint remoteFirewall = FW_UNKNOWN)
    {
        this.rpc = rpc;
        this.pool = pool;
        this.isInitiator = isInitiator;
        this.remoteFirewall = remoteFirewall;
        this.sleeper = new Sleeper();
        addRef(pool.acquire());
    }

    /// The primary punch socket.
    void* socket() nothrow
    {
        return holders[0];
    }

    /// Record what the peer told us over the DHT: are they punching, their NAT
    /// verdict, and the addresses to aim at. `verifiedHost`, if set, marks the
    /// address we've already seen traffic from (safe to spray).
    void updateRemote(bool punching_, uint firewall, Address[] addresses, string verifiedHost = null)
    {
        RemoteAddr[] ra;
        foreach (a; addresses)
            ra ~= RemoteAddr(a.host, a.port, verifiedHost == a.host || isVerified(a.host));
        remoteFirewall = firewall;
        remoteAddresses = ra;
        remoteHolepunching = punching_;
    }

    private bool isVerified(string host) nothrow
    {
        foreach (a; remoteAddresses)
            if (a.verified && a.host == host)
                return true;
        return false;
    }

    /// Kick off the punch. Picks the strategy from the coerced firewall pair and
    /// runs it in the background; returns whether a strategy started.
    bool punch()
    {
        if (done() || remoteAddresses.length == 0)
            return false;

        punching = true;

        immutable local = coerceFirewall(localFirewall);
        immutable remote = coerceFirewall(remoteFirewall);

        RemoteAddr verified;
        bool haveVerified;
        foreach (a; remoteAddresses)
            if (a.verified)
            {
                verified = a;
                haveVerified = true;
                break;
            }

        if (local == FW_CONSISTENT && remote == FW_CONSISTENT)
        {
            runTask(() nothrow { consistentProbe(); });
            return true;
        }

        if (!haveVerified)
            return false;

        if (local == FW_CONSISTENT && remote >= FW_RANDOM)
        {
            incrementRandomized();
            runTask(() nothrow { randomProbes(verified); });
            return true;
        }

        if (local >= FW_RANDOM && remote == FW_CONSISTENT)
        {
            incrementRandomized();
            runTask(() nothrow {
                openBirthdaySockets(verified);
                if (punching)
                    keepAliveRandomNat(verified);
            });
            return true;
        }

        return false;
    }

    private bool done() nothrow
    {
        return destroyed || connected;
    }

    // CONSISTENT × CONSISTENT: slow volley at the peer's fixed mapping.
    private void consistentProbe() nothrow
    {
        if (!isInitiator)
            sleeper.pause(1.seconds); // the server's fast-open ping already fired

        int tries = 0;
        while (punching && tries++ < 10)
        {
            foreach (a; remoteAddresses)
            {
                if (!a.verified && (tries & 3) != 0)
                    continue; // unverified addrs only every 4th tick
                beacon(socket(), Address(a.host, 4, a.port), DEFAULT_TTL);
            }
            if (punching)
                sleeper.pause(1.seconds);
        }
        autoDestroy();
    }

    // CONSISTENT × RANDOM: we're guessable; spray the peer host at random ports.
    private void randomProbes(RemoteAddr r) nothrow
    {
        int tries = 1750; // ~35s at 20ms
        while (punching && tries-- > 0)
        {
            beacon(socket(), Address(r.host, 4, randomPort()), DEFAULT_TTL);
            if (punching)
                sleeper.pause(20.msecs);
        }
        autoDestroy();
    }

    // RANDOM × CONSISTENT: keep all 256 birthday sockets warm at the peer's mapping.
    private void keepAliveRandomNat(RemoteAddr r) nothrow
    {
        size_t i = 0;
        int lowTTLRounds = 1;
        sleeper.pause(100.msecs); // we just bursted; let the sockets settle

        int tries = 1750; // ~35s
        while (punching && tries-- > 0)
        {
            if (i == holders.length)
            {
                i = 0;
                if (lowTTLRounds > 0)
                    lowTTLRounds--;
            }
            beacon(holders[i++], Address(r.host, 4, r.port),
                lowTTLRounds > 0 ? HOLEPUNCH_TTL : DEFAULT_TTL);
            if (punching)
                sleeper.pause(20.msecs);
        }
        autoDestroy();
    }

    // Open up to BIRTHDAY_SOCKETS mappings, each beaconing the peer at low TTL so
    // our NAT opens without the probe reaching them yet.
    private void openBirthdaySockets(RemoteAddr r) nothrow
    {
        while (punching && holders.length < BIRTHDAY_SOCKETS)
        {
            void* s;
            try
                s = pool.acquire();
            catch (Exception)
                return; // pool exhausted / bind failed — stop opening
            addRef(s);
            beacon(s, Address(r.host, 4, r.port), HOLEPUNCH_TTL);
        }
    }

    // Register a pool socket as a punch source and route its inbound beacons here.
    private void addRef(void* s) nothrow
    {
        holders ~= s;
        rpc.onBeacon(s, (Address from) nothrow { onBeacon(from, s); });
    }

    // An inbound HOLEPUNCH beacon: proof the hole toward `from` is open.
    private void onBeacon(Address from, void* s) nothrow
    {
        if (onBeaconTrace !is null)
            onBeaconTrace(false, from, 0, 0);
        if (!isInitiator)
        {
            // Responder: reflect so the initiator's NAT sees return traffic.
            beacon(s, from, DEFAULT_TTL);
            return;
        }
        if (connected)
            return;

        connected = true;
        punching = false;

        // Keep the winning socket; drop the rest.
        foreach (h; holders)
            if (h !is s)
            {
                rpc.onBeacon(h, null);
                try
                    pool.release(h);
                catch (Exception)
                {
                }
            }
        holders = [s];

        decrementRandomized();
        sleeper.resume();
        if (onConnect !is null)
            onConnect(s, from);
    }

    private void autoDestroy() nothrow
    {
        if (!connected)
            destroy();
    }

    // dht._randomPunches rate-limiting is a Stage-E (connect.d) concern; track the
    // flag locally so destroy() balances it.
    private void incrementRandomized() nothrow
    {
        randomized = true;
    }

    private void decrementRandomized() nothrow
    {
        randomized = false;
    }

    void destroy() nothrow
    {
        if (destroyed)
            return;
        destroyed = true;
        punching = false;

        foreach (h; holders)
        {
            rpc.onBeacon(h, null);
            try
                pool.release(h);
            catch (Exception)
            {
            }
        }
        holders = [];
        sleeper.resume(); // wake any loop so it exits

        if (!connected)
        {
            decrementRandomized();
            if (onAbort !is null)
                onAbort();
        }
    }
}

private ushort randomPort() nothrow
{
    try
        return cast(ushort) uniform(1000, 65_536); // [1000, 65536)
    catch (Exception)
        return 1000;
}

private uint coerceFirewall(uint fw) nothrow
{
    return fw == FW_OPEN ? FW_CONSISTENT : fw;
}
