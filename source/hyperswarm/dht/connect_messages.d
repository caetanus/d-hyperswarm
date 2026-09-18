/// The hyperdht peer-handshake wire (lib/messages.js): the `handshake` envelope
/// that carries a Noise message over PEER_HANDSHAKE, and the `noisePayload` that
/// rides inside the Noise handshake (addresses, udx stream id, firewall, holepunch
/// info). This is what two peers exchange to agree on how to open the connection.
module hyperswarm.dht.connect_messages;

import hyperswarm.cenc : State, Uint, Buffer, Fixed, ArrayOf, Ipv4Address, Ipv6Address, Address;

private alias Fixed32 = Fixed!32;
private alias Ipv4Array = ArrayOf!Ipv4Address;
private alias Ipv6Array = ArrayOf!Ipv6Address;

// firewall states (constants.js FIREWALL)
enum : uint
{
    FW_UNKNOWN = 0,
    FW_OPEN = 1,
    FW_CONSISTENT = 2,
    FW_RANDOM = 3
}

// holepunch round error codes (constants.js ERROR)
enum : uint
{
    ERR_NONE = 0,
    ERR_ABORTED = 1,
    ERR_VERSION_MISMATCH = 2,
    ERR_TRY_LATER = 3
}

// ── handshake envelope ───────────────────────────────────────────────────────

struct Handshake
{
    uint mode;
    ubyte[] noise;
    bool hasPeerAddress;
    Address peerAddress;
    bool hasRelayAddress;
    Address relayAddress;
}

ubyte[] encodeHandshake(Handshake m)
{
    State s;
    s.end += 1 + 1 + (m.hasPeerAddress ? 6 : 0) + (m.hasRelayAddress ? 6 : 0);
    Buffer.preencode(s, m.noise);
    s.buffer = new ubyte[](s.end);

    immutable ubyte flags = cast(ubyte)((m.hasPeerAddress ? 1 : 0) | (m.hasRelayAddress ? 2 : 0));
    Uint.encode(s, flags);
    Uint.encode(s, m.mode);
    Buffer.encode(s, m.noise);
    if (m.hasPeerAddress)
        Ipv4Address.encode(s, m.peerAddress);
    if (m.hasRelayAddress)
        Ipv4Address.encode(s, m.relayAddress);
    return s.buffer;
}

Handshake decodeHandshake(ubyte[] buf)
{
    auto s = State(0, buf.length, buf);
    immutable flags = Uint.decode(s);
    Handshake m;
    m.mode = cast(uint) Uint.decode(s);
    m.noise = Buffer.decode(s);
    if (flags & 1)
    {
        m.hasPeerAddress = true;
        m.peerAddress = Ipv4Address.decode(s);
    }
    if (flags & 2)
    {
        m.hasRelayAddress = true;
        m.relayAddress = Ipv4Address.decode(s);
    }
    return m;
}

// ── noisePayload sub-infos ───────────────────────────────────────────────────

struct UdxInfo
{
    uint ver = 1;
    bool reusableSocket;
    uint id;
    uint seq;
}

struct RelayInfo
{
    Address relayAddress;
    Address peerAddress;
}

struct HolepunchInfo
{
    uint id;
    RelayInfo[] relays;
}

struct RelayThroughInfo
{
    ubyte[32] publicKey;
    ubyte[32] token;
}

private void ppUdx(ref State s, UdxInfo m)
{
    s.end += 2;
    Uint.preencode(s, m.id);
    Uint.preencode(s, m.seq);
}

private void encUdx(ref State s, UdxInfo m)
{
    Uint.encode(s, 1);
    Uint.encode(s, m.reusableSocket ? 1 : 0);
    Uint.encode(s, m.id);
    Uint.encode(s, m.seq);
}

private UdxInfo decUdx(ref State s)
{
    UdxInfo m;
    m.ver = cast(uint) Uint.decode(s);
    immutable features = Uint.decode(s);
    m.reusableSocket = (features & 1) != 0;
    m.id = cast(uint) Uint.decode(s);
    m.seq = cast(uint) Uint.decode(s);
    return m;
}

private void ppRelayInfo(ref State s, RelayInfo m)
{
    s.end += 12;
}

private void encRelayInfo(ref State s, RelayInfo m)
{
    Ipv4Address.encode(s, m.relayAddress);
    Ipv4Address.encode(s, m.peerAddress);
}

private RelayInfo decRelayInfo(ref State s)
{
    RelayInfo m;
    m.relayAddress = Ipv4Address.decode(s);
    m.peerAddress = Ipv4Address.decode(s);
    return m;
}

private void ppHolepunch(ref State s, HolepunchInfo m)
{
    Uint.preencode(s, m.id);
    Uint.preencode(s, m.relays.length);
    foreach (r; m.relays)
        ppRelayInfo(s, r);
}

private void encHolepunch(ref State s, HolepunchInfo m)
{
    Uint.encode(s, m.id);
    Uint.encode(s, m.relays.length);
    foreach (r; m.relays)
        encRelayInfo(s, r);
}

private HolepunchInfo decHolepunch(ref State s)
{
    HolepunchInfo m;
    m.id = cast(uint) Uint.decode(s);
    immutable n = cast(size_t) Uint.decode(s);
    foreach (_; 0 .. n)
        m.relays ~= decRelayInfo(s);
    return m;
}

private void ppRelayThrough(ref State s, RelayThroughInfo m)
{
    Uint.preencode(s, 1);
    Uint.preencode(s, 0);
    s.end += 64;
}

private void encRelayThrough(ref State s, RelayThroughInfo m)
{
    Uint.encode(s, 1);
    Uint.encode(s, 0);
    Fixed32.encode(s, m.publicKey[]);
    Fixed32.encode(s, m.token[]);
}

private RelayThroughInfo decRelayThrough(ref State s)
{
    RelayThroughInfo m;
    Uint.decode(s); // version
    Uint.decode(s); // flags
    m.publicKey[] = Fixed32.decode(s)[0 .. 32];
    m.token[] = Fixed32.decode(s)[0 .. 32];
    return m;
}

// ── noisePayload ─────────────────────────────────────────────────────────────

struct NoisePayload
{
    uint ver = 1;
    uint error;
    uint firewall;
    bool hasHolepunch;
    HolepunchInfo holepunch;
    Address[] addresses4;
    Address[] addresses6;
    bool hasUdx;
    UdxInfo udx;
    bool hasSecretStream;
    bool hasRelayThrough;
    RelayThroughInfo relayThrough;
    bool hasRelayAddresses;
    Address[] relayAddresses;
}

ubyte[] encodeNoisePayload(NoisePayload m)
{
    State s;
    s.end += 4; // version + flags + error + firewall
    if (m.hasHolepunch)
        ppHolepunch(s, m.holepunch);
    if (m.addresses4.length)
        Ipv4Array.preencode(s, m.addresses4);
    if (m.addresses6.length)
        Ipv6Array.preencode(s, m.addresses6);
    if (m.hasUdx)
        ppUdx(s, m.udx);
    if (m.hasSecretStream)
        Uint.preencode(s, 1);
    if (m.hasRelayThrough)
        ppRelayThrough(s, m.relayThrough);
    if (m.hasRelayAddresses)
        Ipv4Array.preencode(s, m.relayAddresses);

    s.buffer = new ubyte[](s.end);
    immutable ubyte flags = cast(ubyte)(
        (m.hasHolepunch ? 1 : 0) | (m.addresses4.length ? 2 : 0) | (m.addresses6.length ? 4 : 0)
        | (m.hasUdx ? 8 : 0) | (m.hasSecretStream ? 16 : 0) | (m.hasRelayThrough ? 32 : 0)
        | (m.hasRelayAddresses ? 64 : 0));

    Uint.encode(s, 1); // version
    Uint.encode(s, flags);
    Uint.encode(s, m.error);
    Uint.encode(s, m.firewall);

    if (m.hasHolepunch)
        encHolepunch(s, m.holepunch);
    if (m.addresses4.length)
        Ipv4Array.encode(s, m.addresses4);
    if (m.addresses6.length)
        Ipv6Array.encode(s, m.addresses6);
    if (m.hasUdx)
        encUdx(s, m.udx);
    if (m.hasSecretStream)
        Uint.encode(s, 1);
    if (m.hasRelayThrough)
        encRelayThrough(s, m.relayThrough);
    if (m.hasRelayAddresses)
        Ipv4Array.encode(s, m.relayAddresses);
    return s.buffer;
}

NoisePayload decodeNoisePayload(ubyte[] buf)
{
    auto s = State(0, buf.length, buf);
    NoisePayload m;
    m.ver = cast(uint) Uint.decode(s);
    if (m.ver != 1)
        return m; // unknown version — return as-is, per the reference

    immutable flags = Uint.decode(s);
    m.error = cast(uint) Uint.decode(s);
    m.firewall = cast(uint) Uint.decode(s);

    if (flags & 1)
    {
        m.hasHolepunch = true;
        m.holepunch = decHolepunch(s);
    }
    if (flags & 2)
        m.addresses4 = Ipv4Array.decode(s);
    if (flags & 4)
        m.addresses6 = Ipv6Array.decode(s);
    if (flags & 8)
    {
        m.hasUdx = true;
        m.udx = decUdx(s);
    }
    if (flags & 16)
    {
        m.hasSecretStream = true;
        Uint.decode(s);
    }
    if (flags & 32)
    {
        m.hasRelayThrough = true;
        m.relayThrough = decRelayThrough(s);
    }
    if (flags & 64)
    {
        m.hasRelayAddresses = true;
        m.relayAddresses = Ipv4Array.decode(s);
    }
    return m;
}

// ── holepunch envelope + payload (lib/messages.js, over PEER_HOLEPUNCH) ───────

/// The PEER_HOLEPUNCH message envelope: routed like the handshake, it carries the
/// holepunchSecret-encrypted `payload` between the two peers during a punch.
struct Holepunch
{
    uint mode;
    uint id;
    ubyte[] payload;
    bool hasPeerAddress;
    Address peerAddress;
}

ubyte[] encodeHolepunch(Holepunch m)
{
    State s;
    s.end += 2; // flags + mode
    Uint.preencode(s, m.id);
    Buffer.preencode(s, m.payload);
    if (m.hasPeerAddress)
        s.end += 6;

    s.buffer = new ubyte[](s.end);
    Uint.encode(s, m.hasPeerAddress ? 1 : 0);
    Uint.encode(s, m.mode);
    Uint.encode(s, m.id);
    Buffer.encode(s, m.payload);
    if (m.hasPeerAddress)
        Ipv4Address.encode(s, m.peerAddress);
    return s.buffer;
}

Holepunch decodeHolepunch(ubyte[] buf)
{
    auto s = State(0, buf.length, buf);
    immutable flags = Uint.decode(s);
    Holepunch m;
    m.mode = cast(uint) Uint.decode(s);
    m.id = cast(uint) Uint.decode(s);
    m.payload = Buffer.decode(s);
    if (flags & 1)
    {
        m.hasPeerAddress = true;
        m.peerAddress = Ipv4Address.decode(s);
    }
    return m;
}

/// The holepunch payload (encrypted inside `Holepunch.payload`): the NAT/punch
/// state the two sides exchange each round (firewall, addresses, tokens, …).
struct HolepunchPayload
{
    uint error;
    uint firewall;
    uint round;
    bool connected;
    bool punching;
    Address[] addresses;
    bool hasRemoteAddress;
    Address remoteAddress;
    ubyte[] token; // 32 bytes, or null
    ubyte[] remoteToken; // 32 bytes, or null
}

ubyte[] encodeHolepunchPayload(HolepunchPayload m)
{
    State s;
    s.end += 4; // flags + error + firewall + round
    if (m.addresses.length)
        Ipv4Array.preencode(s, m.addresses);
    if (m.hasRemoteAddress)
        s.end += 6;
    if (m.token.length)
        s.end += 32;
    if (m.remoteToken.length)
        s.end += 32;

    s.buffer = new ubyte[](s.end);
    immutable ubyte flags = cast(ubyte)(
        (m.connected ? 1 : 0) | (m.punching ? 2 : 0) | (m.addresses.length ? 4 : 0)
        | (m.hasRemoteAddress ? 8 : 0) | (m.token.length ? 16 : 0) | (m.remoteToken.length ? 32 : 0));
    Uint.encode(s, flags);
    Uint.encode(s, m.error);
    Uint.encode(s, m.firewall);
    Uint.encode(s, m.round);
    if (m.addresses.length)
        Ipv4Array.encode(s, m.addresses);
    if (m.hasRemoteAddress)
        Ipv4Address.encode(s, m.remoteAddress);
    if (m.token.length)
        Fixed32.encode(s, m.token);
    if (m.remoteToken.length)
        Fixed32.encode(s, m.remoteToken);
    return s.buffer;
}

HolepunchPayload decodeHolepunchPayload(ubyte[] buf)
{
    auto s = State(0, buf.length, buf);
    immutable flags = Uint.decode(s);
    HolepunchPayload m;
    m.error = cast(uint) Uint.decode(s);
    m.firewall = cast(uint) Uint.decode(s);
    m.round = cast(uint) Uint.decode(s);
    m.connected = (flags & 1) != 0;
    m.punching = (flags & 2) != 0;
    if (flags & 4)
        m.addresses = Ipv4Array.decode(s);
    if (flags & 8)
    {
        m.hasRemoteAddress = true;
        m.remoteAddress = Ipv4Address.decode(s);
    }
    if (flags & 16)
        m.token = Fixed32.decode(s);
    if (flags & 32)
        m.remoteToken = Fixed32.decode(s);
    return m;
}
