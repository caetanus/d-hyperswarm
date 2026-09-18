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
import hyperswarm.dht.holepuncher : Holepuncher;
import hyperswarm.dht.secure_payload : SecurePayload;
import hyperswarm.dht.connect_messages : Holepunch, HolepunchPayload,
    FW_UNKNOWN, FW_OPEN, FW_CONSISTENT, ERR_NONE, ERR_ABORTED;

final class HolepunchSession
{
    Holepuncher puncher;
    SecurePayload payload;
    uint round;
    bool destroyed;

    this(Rpc rpc, SocketPool pool, ubyte[32] holepunchSecret, bool isInitiator,
        uint remoteFirewall = FW_UNKNOWN)
    {
        puncher = new Holepuncher(rpc, pool, isInitiator, remoteFirewall);
        payload = new SecurePayload(holepunchSecret);
    }

    /// Sample our own external mapping + NAT verdict off the DHT before the round
    /// (server does this when it registers the session; client after the handshake).
    void sample(Address[] seeds, Duration timeout = 2.seconds)
    {
        puncher.sample(seeds, timeout);
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

        // Fast mode: if we're consistent and the peer opened a session to the address
        // we advertise, fire a quick beacon back to pin our outbound (the same
        // fast-open ping that fixed the rig's second-mover fork).
        if (coerce(p.nat.firewall) == FW_CONSISTENT && remote.hasRemoteAddress
            && addrIn(p.nat.addresses, remote.remoteAddress))
            p.ping(peerAddress);

        if (p.remoteHolepunching)
            p.punch();

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
