/// The dht-rpc packet wire (holepunchto/dht-rpc, pin 2eca6d7, lib/io.js): the
/// request/response datagrams a Kademlia node exchanges. These ride plain UDP
/// datagrams (a udx socket's send is a UDP send), so our compact-encoding codec is
/// all that's needed on the wire. Node IDs are BLAKE2b(ipv4 ++ port).
///
/// Packet = [type|version byte][flags byte][uint16 tid][ipv4 addr] then, gated by
/// flags: [id fixed32][token fixed32]([target fixed32] for requests / [closerNodes]
/// for replies)[command uint (requests)][error uint (replies)][value buffer].
module hyperswarm.dht.wire;

import hyperswarm.cenc : State, Uint, Uint16, Ipv4Address, Fixed, Buffer, ArrayOf, Address;
import hyperswarm.noise.crypto : keyedBlake2b;

enum ubyte VERSION = 0b11;
enum ubyte REQUEST_ID = (0b0000 << 4) | VERSION; // 0x03
enum ubyte RESPONSE_ID = (0b0001 << 4) | VERSION; // 0x13

// Internal commands (lib/commands.js).
enum : uint
{
    PING = 0,
    PING_NAT = 1,
    FIND_NODE = 2,
    DOWN_HINT = 3,
    DELAYED_PING = 4
}

private alias Fixed32 = Fixed!32;
private alias Ipv4Array = ArrayOf!Ipv4Address;

/// A node's 32-byte routing id: BLAKE2b of the 6-byte address (4 IPv4 bytes + a
/// little-endian uint16 port), per dht-rpc lib/peer.js.
ubyte[32] nodeId(string host, ushort port)
{
    ubyte[6] addr;
    auto s = State(0, 6, addr[]);
    Ipv4Address.encode(s, Address(host, 4, port));
    ubyte[32] id;
    keyedBlake2b(id[], addr[], []);
    return id;
}

/// Encode a request datagram. `target`/`value`/`token`/`id` are optional (pass
/// null to omit); `internal` marks a built-in command.
ubyte[] encodeRequest(ushort tid, Address to, uint command,
    scope const(ubyte)[] target = null, scope const(ubyte)[] value = null,
    scope const(ubyte)[] token = null, scope const(ubyte)[] id = null, bool internal = true)
{
    State s;
    s.end = 1 + 1 + 6 + 2; // type + flags + ipv4 to + uint16 tid
    if (id.length)
        s.end += 32;
    if (token.length)
        s.end += 32;
    Uint.preencode(s, command);
    if (target.length)
        s.end += 32;
    if (value.length)
        Buffer.preencode(s, value);

    s.buffer = new ubyte[](s.end);
    s.buffer[s.start++] = REQUEST_ID;
    s.buffer[s.start++] = cast(ubyte)(
        (id.length ? 1 : 0) | (token.length ? 2 : 0) | (internal ? 4 : 0)
        | (target.length ? 8 : 0) | (value.length ? 16 : 0));

    Uint16.encode(s, tid);
    Ipv4Address.encode(s, to);
    if (id.length)
        Fixed32.encode(s, id);
    if (token.length)
        Fixed32.encode(s, token);
    Uint.encode(s, command);
    if (target.length)
        Fixed32.encode(s, target);
    if (value.length)
        Buffer.encode(s, value);
    return s.buffer;
}

/// Encode a reply datagram (the responder side). `to` is the requester's address
/// as we observed it (NAT detection); `id`/`token`/`closerNodes`/`value` are
/// optional; a non-zero `error` is included.
ubyte[] encodeReply(ushort tid, Address to, scope const(ubyte)[] id = null,
    scope const(ubyte)[] token = null, Address[] closerNodes = null,
    uint error = 0, scope const(ubyte)[] value = null)
{
    State s;
    s.end = 1 + 1 + 6 + 2; // type + flags + ipv4 to + uint16 tid
    if (id.length)
        s.end += 32;
    if (token.length)
        s.end += 32;
    if (closerNodes.length)
        Ipv4Array.preencode(s, closerNodes);
    if (error)
        Uint.preencode(s, error);
    if (value.length)
        Buffer.preencode(s, value);

    s.buffer = new ubyte[](s.end);
    s.buffer[s.start++] = RESPONSE_ID;
    s.buffer[s.start++] = cast(ubyte)(
        (id.length ? 1 : 0) | (token.length ? 2 : 0) | (closerNodes.length ? 4 : 0)
        | (error ? 8 : 0) | (value.length ? 16 : 0));

    Uint16.encode(s, tid);
    Ipv4Address.encode(s, to);
    if (id.length)
        Fixed32.encode(s, id);
    if (token.length)
        Fixed32.encode(s, token);
    if (closerNodes.length)
        Ipv4Array.encode(s, closerNodes);
    if (error)
        Uint.encode(s, error);
    if (value.length)
        Buffer.encode(s, value);
    return s.buffer;
}

/// A decoded reply datagram.
struct Reply
{
    ushort tid;
    Address to; // our address as the responder saw it (NAT detection)
    ubyte[] id; // responder's node id, or null
    ubyte[] token;
    Address[] closerNodes;
    uint error;
    ubyte[] value;
}

/// Decode a reply datagram (must start with RESPONSE_ID). Throws on a malformed
/// packet or one that is not a response.
Reply decodeReply(ubyte[] buf)
{
    if (buf.length < 2 || buf[0] != RESPONSE_ID)
        throw new Exception("dht: not a response packet");
    auto s = State(1, buf.length, buf);
    immutable flags = Uint.decode(s);
    Reply r;
    r.tid = cast(ushort) Uint16.decode(s);
    r.to = Ipv4Address.decode(s);
    if (flags & 1)
        r.id = Fixed32.decode(s);
    if (flags & 2)
        r.token = Fixed32.decode(s);
    if (flags & 4)
        r.closerNodes = Ipv4Array.decode(s);
    if (flags & 8)
        r.error = cast(uint) Uint.decode(s);
    if (flags & 16)
        r.value = Buffer.decode(s);
    return r;
}

/// A decoded request datagram (for implementing a node / testing round-trips).
struct RequestPacket
{
    ushort tid;
    Address to;
    ubyte[] id;
    ubyte[] token;
    uint command;
    ubyte[] target;
    ubyte[] value;
    bool internal;
}

/// Decode a request datagram (must start with REQUEST_ID).
RequestPacket decodeRequest(ubyte[] buf)
{
    if (buf.length < 2 || buf[0] != REQUEST_ID)
        throw new Exception("dht: not a request packet");
    auto s = State(1, buf.length, buf);
    immutable flags = Uint.decode(s);
    RequestPacket r;
    r.internal = (flags & 4) != 0;
    r.tid = cast(ushort) Uint16.decode(s);
    r.to = Ipv4Address.decode(s);
    if (flags & 1)
        r.id = Fixed32.decode(s);
    if (flags & 2)
        r.token = Fixed32.decode(s);
    r.command = cast(uint) Uint.decode(s);
    if (flags & 8)
        r.target = Fixed32.decode(s);
    if (flags & 16)
        r.value = Buffer.decode(s);
    return r;
}
