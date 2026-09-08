/// hyperdht's announce wire + signing, byte-exact vs the reference
/// (tests/hdht_vectors.d): the peer record encoding, the ed25519 announce
/// signature the storing nodes verify (deterministic, so vectorable), and the full
/// signed announce. Also a verify round-trip.
module tests.hdht_messages_test;

import fluent.asserts;
import hyperswarm.dht.messages;
import hyperswarm.noise.crypto : ed25519Keypair, Keypair;
import hyperswarm.cenc : Address;
import tests.hdht_vectors;
import std.format : format;

private string toHex(scope const(ubyte)[] b)
{
    string r;
    foreach (x; b)
        r ~= format("%02x", x);
    return r;
}

private string expect(string name)
{
    foreach (ref v; hdhtVectors)
        if (v.name == name)
            return v.hex;
    assert(0, "missing vector: " ~ name);
}

@("hyperdht: peer encoding + announce signature are byte-exact")
unittest
{
    ubyte[32] seed = 3;
    auto kp = ed25519Keypair(seed[]);
    toHex(kp.publicKey[]).should.equal(expect("pubkey_seed3"));

    PeerRecord peer;
    peer.publicKey = kp.publicKey;
    peer.relayAddresses = [Address("1.2.3.4", 4, 5)];
    toHex(encodePeer(peer)).should.equal(expect("peer_enc"));

    ubyte[32] target = 0xaa, token = 0xbb, id = 0xcc;
    auto sig = signAnnounce(target[], token[], id[], peer, kp);
    toHex(sig[]).should.equal(expect("sign_announce"));

    // the storing node verifies with the peer's public key
    verifyAnnounce(target[], token[], id[], peer, sig[]).should.equal(true);

    Announce ann;
    ann.hasPeer = true;
    ann.peer = peer;
    ann.hasSignature = true;
    ann.signature = sig;
    toHex(encodeAnnounce(ann)).should.equal(expect("announce_signed"));
}

@("hyperdht: lookup reply decodes the peer records our announce produced")
unittest
{
    // round-trip: an announce's peer, wrapped as a one-peer lookup reply value.
    ubyte[32] seed = 7;
    auto kp = ed25519Keypair(seed[]);
    PeerRecord peer;
    peer.publicKey = kp.publicKey;
    peer.relayAddresses = [Address("9.8.7.6", 4, 4242)];

    // build a lookup reply value manually: uint count(1) + peer, no bump
    import hyperswarm.cenc : State, Uint, Fixed, ArrayOf, Ipv4Address;

    State s;
    Uint.preencode(s, 1);
    Fixed!32.preencode(s, peer.publicKey[]);
    ArrayOf!Ipv4Address.preencode(s, peer.relayAddresses);
    s.buffer = new ubyte[](s.end);
    Uint.encode(s, 1);
    Fixed!32.encode(s, peer.publicKey[]);
    ArrayOf!Ipv4Address.encode(s, peer.relayAddresses);

    auto reply = decodeLookupReply(s.buffer);
    reply.peers.length.should.equal(1);
    reply.peers[0].publicKey.should.equal(kp.publicKey);
    reply.peers[0].relayAddresses[0].host.should.equal("9.8.7.6");
    reply.peers[0].relayAddresses[0].port.should.equal(4242);
}
