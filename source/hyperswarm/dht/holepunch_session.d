/// One half-open holepunch session — hyperdht's `_holepunches[id]` entry: a
/// Holepuncher + the SecurePayload that seals each PEER_HOLEPUNCH round, plus the
/// round counter. `handleRound` is the port of server.js `_onpeerholepunch`'s core:
/// decrypt the peer's round, feed our NAT sampler, updateRemote, fire the fast-open
/// ping, punch, and seal the reply. Server-side today (isInitiator=false); the
/// client round loop (E2) reuses the same session + round-step.
///
/// Deferred vs hyperdht (noted, not needed for the CONSISTENT rig path): the async
/// `analyze()`/reopen loop (our sample() is synchronous), and the random-punch rate
/// limiter (dht._randomPunches / TRY_LATER gate).
module hyperswarm.dht.holepunch_session;

import std.typecons : Nullable, nullable;
import core.time : Duration, seconds;

import hyperswarm.cenc : Address;
import hyperswarm.dht.rpc : Rpc;
import hyperswarm.dht.socket_pool : SocketPool;
import hyperswarm.dht.holepuncher : Holepuncher, RandomPunchGate;
import hyperswarm.dht.secure_payload : SecurePayload;
import hyperswarm.dht.connect_messages : Holepunch, HolepunchPayload,
    FW_UNKNOWN, FW_OPEN, FW_CONSISTENT, ERR_NONE, ERR_ABORTED, ERR_TRY_LATER;

final class HolepunchSession
{
    Holepuncher puncher;
    SecurePayload payload;
    uint round;
    bool destroyed;

    this(Rpc rpc, SocketPool pool, ubyte[32] holepunchSecret, bool isInitiator,
        uint remoteFirewall = FW_UNKNOWN, RandomPunchGate gate = null)
    {
        puncher = new Holepuncher(rpc, pool, isInitiator, remoteFirewall, gate);
        payload = new SecurePayload(holepunchSecret);
    }

    /// Wrap a puncher that already exists (the client samples its NAT before the
    /// handshake to advertise its firewall, then learns the holepunchSecret from the
    /// handshake reply and assembles the session around that same puncher).
    this(Holepuncher puncher, SecurePayload payload)
    {
        this.puncher = puncher;
        this.payload = payload;
    }

    /// Sample our own external mapping + NAT verdict off the DHT before the round
    /// (server does this when it registers the session; client after the handshake).
    void sample(Address[] seeds, Duration timeout = 2.seconds, Duration budget = Duration.max)
    {
        puncher.sample(seeds, timeout, budget);
    }

    /// Process one inbound PEER_HOLEPUNCH round and return the sealed reply payload
    /// (or null to drop). `reqTo` is our external as the relay/peer saw us, `reqFrom`
    /// is the sender; `viaOurSocket` = the datagram arrived on the puncher's own
    /// socket (so reqTo is a real NAT sample). `isServerRelay` = the sender is one of
    /// our announce relays (its token echo is trustworthy).
    Nullable!(ubyte[]) handleRound(Holepunch incoming, Address reqTo, Address reqFrom,
        bool viaOurSocket, bool isServerRelay)
    {
        if (destroyed || !incoming.hasPeerAddress)
            return Nullable!(ubyte[]).init;
        auto peerAddress = incoming.peerAddress;

        auto rpn = payload.decrypt(incoming.payload);
        if (rpn.isNull)
            return Nullable!(ubyte[]).init;
        auto remote = rpn.get;

        auto p = puncher;
        if (remote.error != ERR_NONE)
        {
            if (remote.round >= round)
                round = remote.round;
            return abort();
        }

        auto token = payload.token(peerAddress);
        immutable echoed = isServerRelay && remote.remoteToken.length
            && remote.remoteToken == token;

        if (viaOurSocket)
            p.nat.add(reqTo, reqFrom); // our external as this relay/peer observed us

        if (remote.round >= round)
        {
            round = remote.round;
            p.updateRemote(remote.punching, remote.firewall, remote.addresses,
                echoed ? peerAddress.host : null);
        }

        // Open our NAT mapping toward the peer's punch socket NOW, from the round it
        // announced it in: a low-TTL beacon that dies in transit but leaves the
        // mapping behind. The peer starts beaconing us as soon as it has our reply;
        // behind a conntrack NAT (Docker, most home routers) the first inbound packet
        // to a port we have not yet sent from books that tuple, and our own later
        // send gets a fresh port — the hole misses. Being first costs one packet.
        p.openSession(peerAddress);
        // Fast mode: if we're consistent and the peer opened a session to the address
        // we advertise, fire a real beacon back too (hyperdht's fast-open ping).
        if (coerce(p.nat.firewall) == FW_CONSISTENT && remote.hasRemoteAddress
            && addrIn(p.nat.addresses, remote.remoteAddress))
            p.ping(peerAddress);

        if (p.remoteHolepunching)
        {
            // server.js: a random punch while the DHT-wide gate is busy is answered
            // TRY_LATER — as an abort, since there is no relay-through to retry over.
            auto gate = p.randomGate();
            // Only a NEW random punch is throttled: if THIS puncher already holds the
            // gate slot (a replayed/duplicate round), re-run its memoized punch()
            // instead of aborting it against its own reservation.
            if (p.isRandomPunch() && !p.punchInProgress() && gate !is null && gate.busy())
                return abort(ERR_TRY_LATER);
            immutable started = p.punch();
            if (p.destroyed)
                return Nullable!(ubyte[]).init;
            // Abort only when we actually had a verdict and still could not punch
            // (genuinely unpunchable). Before our own NAT sample lands (firewall
            // UNKNOWN) a round cannot pick a strategy yet — seal a normal reply and
            // let a later round drive the punch once sampling has a verdict.
            if (!started && p.nat.firewall != FW_UNKNOWN)
                return abort();
        }

        if (p.nat.firewall != FW_UNKNOWN)
            p.nat.freeze(); // freeze the verdict we're handing the peer

        HolepunchPayload reply;
        reply.error = ERR_NONE;
        reply.firewall = p.nat.firewall;
        reply.round = round;
        reply.connected = p.connected;
        reply.punching = p.punching;
        reply.addresses = p.nat.addresses;
        if (isServerRelay)
            reply.token = token;
        reply.remoteToken = remote.token;
        return nullable(payload.encrypt(reply));
    }

    /// Client side, outgoing half of one round (hyperdht updateHolepunch's request):
    /// seal our current NAT state to send to the server through the relay.
    /// `remoteAddress` = where we currently think the server is (its advertised addr).
    /// `punching` announces we're about to punch (probe rounds send false to exchange
    /// NAT state first; the punch round sends true so the server punches with us).
    /// `token` = our token for the server's address (the punch round; null in a
    /// probe), `remoteToken` = the token the server minted for us in its last reply,
    /// echoed back so it can verify our address.
    ubyte[] buildClientRound(Address remoteAddress, bool punching = false,
        ubyte[] token = null, ubyte[] remoteToken = null)
    {
        HolepunchPayload m;
        m.error = ERR_NONE;
        m.firewall = puncher.nat.firewall;
        m.round = round++;
        m.connected = false;
        m.punching = punching;
        m.addresses = puncher.nat.addresses;
        m.hasRemoteAddress = remoteAddress.host.length != 0;
        m.remoteAddress = remoteAddress;
        m.token = token;
        m.remoteToken = remoteToken;
        return payload.encrypt(m);
    }

    /// What the client learns from one round reply.
    struct RoundReply
    {
        bool ok; /// decrypted and error-free
        uint error;
        ubyte[] token; /// the server's token for our address (echo it next round)
        bool tryLater;
    }

    /// Client side, incoming half of one round: process the server's sealed reply.
    /// `replyTo`/`replyFrom` = the relay's view of us (a NAT sample). Returns false on
    /// error/undecryptable (caller aborts), true to keep going. On success it learns
    /// the server's firewall + addresses (verified-address / token-echo deferred, so
    /// the peer addresses are probed rather than sprayed — fine for the CONSISTENT
    /// path). Call puncher.punch() after, once both sides know each other.
    /// `sentToken` = the token we put in the request (punch round), `peerHost` = the
    /// server address we sent it for: when the server echoes it back the address is
    /// verified (hyperdht updateHolepunch).
    RoundReply applyReply(scope const(ubyte)[] sealed, Address replyTo, Address replyFrom,
        ubyte[] sentToken = null, string peerHost = null)
    {
        RoundReply r;
        auto rpn = payload.decrypt(sealed);
        if (rpn.isNull)
            return r;
        auto remote = rpn.get;
        r.error = remote.error;
        if (remote.error == ERR_TRY_LATER)
        {
            r.tryLater = true;
            return r;
        }
        if (remote.error != ERR_NONE)
            return r;
        auto p = puncher;
        p.nat.add(replyTo, replyFrom); // our external as the relay observed us
        immutable echoed = sentToken.length && remote.remoteToken.length
            && remote.remoteToken == sentToken;
        p.updateRemote(remote.punching, remote.firewall, remote.addresses,
            echoed ? peerHost : null);
        r.token = remote.token;
        r.ok = true;
        return r;
    }

    /// Seal an abort reply and tear the puncher down.
    Nullable!(ubyte[]) abort(uint error = ERR_ABORTED)
    {
        HolepunchPayload p;
        p.error = error;
        p.firewall = FW_UNKNOWN;
        p.round = round;
        auto sealed = payload.encrypt(p);
        destroy();
        return nullable(sealed);
    }

    void destroy() nothrow
    {
        if (destroyed)
            return;
        destroyed = true;
        puncher.destroy();
    }
}

private uint coerce(uint fw) nothrow
{
    return fw == FW_OPEN ? FW_CONSISTENT : fw;
}

private bool addrIn(Address[] addrs, Address a) nothrow
{
    foreach (x; addrs)
        if (x.host == a.host && x.port == a.port)
            return true;
    return false;
}
