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
