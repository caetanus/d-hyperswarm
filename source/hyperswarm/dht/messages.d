/// hyperdht's announce/lookup wire (holepunchto/hyperdht, pin b4da95c, lib/messages.js
/// + lib/persistent.js): the peer record, the signed announce, the lookup reply, and
/// the announce signable. A node announces itself under a topic with an ed25519
/// signature the storing nodes verify; a lookup returns the peer records.
module hyperswarm.dht.messages;

import hyperswarm.cenc : State, Uint, Fixed, ArrayOf, Ipv4Address, Address;
import hyperswarm.noise.crypto : keyedBlake2b, blake2bBatch, ed25519Sign, ed25519Verify, Keypair;

private alias Fixed32 = Fixed!32;
private alias Fixed64 = Fixed!64;
private alias Ipv4Array = ArrayOf!Ipv4Address;

// Namespaces: hypercore-crypto namespace('hyperswarm/dht', [ANNOUNCE=4, UNANNOUNCE=5,
// ...]) — NS[i] = BLAKE2b(BLAKE2b("hyperswarm/dht") ++ [id]).
private __gshared ubyte[32] NS_ANNOUNCE;
private __gshared ubyte[32] NS_UNANNOUNCE;

shared static this() @trusted
{
    ubyte[32] ns;
    keyedBlake2b(ns[], cast(const(ubyte)[]) "hyperswarm/dht", []);
    ubyte[33] tmp;
    tmp[0 .. 32] = ns[];
    tmp[32] = 4; // COMMANDS.ANNOUNCE
    keyedBlake2b(NS_ANNOUNCE[], tmp[], []);
    tmp[32] = 5; // COMMANDS.UNANNOUNCE
    keyedBlake2b(NS_UNANNOUNCE[], tmp[], []);
}

/// A peer record: an ed25519 public key + relay addresses.
struct PeerRecord
{
    ubyte[32] publicKey;
    Address[] relayAddresses;
}

/// `m.peer` — fixed32 publicKey + ipv4Array relayAddresses.
ubyte[] encodePeer(PeerRecord p)
{
    State s;
    Fixed32.preencode(s, p.publicKey[]);
    Ipv4Array.preencode(s, p.relayAddresses);
    s.buffer = new ubyte[](s.end);
    Fixed32.encode(s, p.publicKey[]);
    Ipv4Array.encode(s, p.relayAddresses);
    return s.buffer;
}

/// A signed announce record (`m.announce`).
struct Announce
{
    bool hasPeer;
    PeerRecord peer;
    bool hasRefresh;
    ubyte[32] refresh;
    bool hasSignature;
    ubyte[64] signature;
    uint bump;
}

ubyte[] encodeAnnounce(Announce a)
{
    State s;
    s.end++; // flags byte
    if (a.hasPeer)
    {
        Fixed32.preencode(s, a.peer.publicKey[]);
        Ipv4Array.preencode(s, a.peer.relayAddresses);
    }
    if (a.hasRefresh)
        s.end += 32;
    if (a.hasSignature)
        s.end += 64;
    if (a.bump)
        Uint.preencode(s, a.bump);

    s.buffer = new ubyte[](s.end);
    immutable ubyte flags = cast(ubyte)(
        (a.hasPeer ? 1 : 0) | (a.hasRefresh ? 2 : 0) | (a.hasSignature ? 4 : 0) | (a.bump ? 8 : 0));
    Uint.encode(s, flags);
    if (a.hasPeer)
    {
        Fixed32.encode(s, a.peer.publicKey[]);
        Ipv4Array.encode(s, a.peer.relayAddresses);
    }
    if (a.hasRefresh)
        Fixed32.encode(s, a.refresh[]);
    if (a.hasSignature)
        Fixed64.encode(s, a.signature[]);
    if (a.bump)
        Uint.encode(s, a.bump);
    return s.buffer;
}

/// The reply value of a LOOKUP query: the peer records (+ a bump counter).
struct LookupReply
{
    PeerRecord[] peers;
    uint bump;
}

LookupReply decodeLookupReply(ubyte[] value)
{
    auto s = State(0, value.length, value);
    immutable count = cast(size_t) Uint.decode(s);
    LookupReply r;
    foreach (_; 0 .. count)
    {
        PeerRecord p;
        p.publicKey[] = Fixed32.decode(s)[0 .. 32];
        p.relayAddresses = Ipv4Array.decode(s);
        r.peers ~= p;
    }
    if (s.start < s.end)
        r.bump = cast(uint) Uint.decode(s);
    return r;
}

/// The 64-byte announce signable: NS(32) ++ BLAKE2b(target, id, token, peerEnc,
/// refresh|∅). `id` is the storing node's id, `token` its per-request token.
ubyte[64] announceSignable(scope const(ubyte)[] target, scope const(ubyte)[] token,
    scope const(ubyte)[] id, PeerRecord peer, scope const(ubyte)[] refresh, bool unannounce = false) @trusted
{
    ubyte[64] signable;
    signable[0 .. 32] = unannounce ? NS_UNANNOUNCE[] : NS_ANNOUNCE[];
    auto peerEnc = encodePeer(peer);
    blake2bBatch(signable[32 .. 64], [target, id, token, cast(const(ubyte)[]) peerEnc, refresh]);
    return signable;
}

/// Sign an announce for a given storing node (target topic, its token + id).
ubyte[64] signAnnounce(scope const(ubyte)[] target, scope const(ubyte)[] token,
    scope const(ubyte)[] id, PeerRecord peer, Keypair keyPair, bool unannounce = false) @trusted
{
    auto signable = announceSignable(target, token, id, peer, null, unannounce);
    ubyte[64] sig;
    ed25519Sign(sig, signable[], keyPair.secretKey[]);
    return sig;
}

/// Verify an announce signature (as the storing node does).
bool verifyAnnounce(scope const(ubyte)[] target, scope const(ubyte)[] token,
    scope const(ubyte)[] id, PeerRecord peer, scope const(ubyte)[] signature, bool unannounce = false) @trusted
{
    auto signable = announceSignable(target, token, id, peer, null, unannounce);
    return ed25519Verify(signature, signable[], peer.publicKey[]);
}
