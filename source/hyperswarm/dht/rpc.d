/// The dht-rpc RPC layer over a udx SOCKET (not a bare UDP socket): send a request
/// datagram with a fresh transaction id and await the matching reply. This matters
/// for connect — hyperdht runs dht-rpc and the connection's udx streams on ONE udx
/// socket, so the address a server sees a handshake come from (req.from) is the very
/// socket the client's stream lives on. We do the same: the udx socket carries both
/// the rpc datagrams (udx delivers non-stream packets to its recv callback) and the
/// connection streams, so a peer that connects back to our rpc source reaches our
/// stream socket.
///
/// A recv callback decodes incoming replies and wakes the waiting request by tid.
/// The udx instance + socket are exposed so the connection layer opens its streams
/// on the same socket.
module hyperswarm.dht.rpc;

import hyperswarm.dht.wire;
import hyperswarm.cenc : Address;
import hyperswarm.udx.udx;
import hyperswarm.udx.facade : Loop, uv_buf_t;
import vibe.core.sync : LocalManualEvent, createManualEvent;
import vibe.core.core : runTask;
import vibe.core.net : resolveHost, NetworkAddress;
import core.time : Duration, seconds;
import core.sys.posix.sys.socket : sockaddr, sockaddr_storage, AF_INET;
import core.sys.posix.netinet.in_ : sockaddr_in;
import core.sys.posix.arpa.inet : htons, ntohs;
import std.format : format;

// Route the udx socket's non-stream datagrams (dht-rpc replies) to the owning Rpc.
// Cooperative single-threaded (the facade loop + callbacks run on one vibe thread),
// so the registry needs no lock.
private __gshared Rpc[void*] g_rpcBySock;

extern (C) void hsRpcRecv(void* socket, ptrdiff_t len, const(uv_buf_t)* buf, const(void)* from) nothrow
{
    if (len <= 0)
        return;
    if (auto r = socket in g_rpcBySock)
        r.onDatagram(cast(ubyte[]) buf.base[0 .. len], from);
}

private Address addrFromSockaddr(const(void)* sa) nothrow
{
    auto sin = cast(const(sockaddr_in)*) sa;
    immutable a = sin.sin_addr.s_addr; // network byte order
    auto b = *cast(const(ubyte[4])*)&a;
    string host;
    try
        host = format("%d.%d.%d.%d", b[0], b[1], b[2], b[3]);
    catch (Exception)
    {
    }
    return Address(host, 4, ntohs(sin.sin_port));
}

extern (C) void hsRpcSockClose(void* s) nothrow {}

final class Rpc
{
    Loop loop;
    private ubyte[] udx; // opaque udx instance
    private ubyte[] sock; // opaque udx socket (rpc datagrams + connection streams)
    private ushort _localPort;
    private ushort nextTid = 1;
    private bool running;

    private static final class Pending
    {
        LocalManualEvent ev;
        Reply reply;
        bool got;
        string expectHost; // resolved IP we sent to; a reply must come from it
        ushort expectPort;
    }

    private Pending[ushort] pending;

    /// Set to act as a dht-rpc server: invoked for each incoming REQUEST datagram
    /// with the decoded request and the sender's address. Reply with `send`.
    void delegate(RequestPacket req, Address from) nothrow onRequest;

    // udx may reference a send buffer until the datagram is flushed; keep the last
    // N (req block + payload) alive in a ring. dht-rpc is low volume, so by the time
    // a slot is reused its send is long done.
    private enum SEND_RING = 256;
    private ubyte[][] sendKeep;
    private size_t sendIdx;

    this(ushort bindPort = 0)
    {
        loop = new Loop();
        runTask(() nothrow { try loop.run(); catch (Exception) {} });

        udx = new ubyte[](hs_udx_sizeof_udx());
        hs_udx_init(loop.chandle, udx.ptr, null);
        sock = new ubyte[](hs_udx_sizeof_socket());
        hs_udx_socket_init(udx.ptr, sock.ptr, &hsRpcSockClose);

        sockaddr_in b;
        b.sin_family = AF_INET;
        b.sin_addr.s_addr = 0; // INADDR_ANY
        b.sin_port = htons(bindPort);
        // Fail loudly rather than returning a zombie that only ever times out (e.g.
        // the port is in use).
        if (hs_udx_socket_bind(sock.ptr, cast(sockaddr*)&b, 0) != 0)
            throw new Exception("dht-rpc: udx socket bind failed");
        sockaddr_storage ss;
        int sl = cast(int) ss.sizeof;
        if (hs_udx_socket_getsockname(sock.ptr, &ss, &sl) != 0)
            throw new Exception("dht-rpc: getsockname failed");
        _localPort = ntohs((cast(sockaddr_in*)&ss).sin_port);
        if (_localPort == 0)
            throw new Exception("dht-rpc: bound to port 0");

        sendKeep.length = SEND_RING;
        g_rpcBySock[sock.ptr] = this;
        running = true;
        hs_udx_socket_recv_start(sock.ptr, &hsRpcRecv);
    }

    ushort localPort()
    {
        return _localPort;
    }

    /// The udx instance the rpc socket lives on — the connection layer opens its
    /// streams on this same instance/socket so its stream source is our rpc source.
    void* udxPtr()
    {
        return udx.ptr;
    }

    void* sockPtr()
    {
        return sock.ptr;
    }

    void close()
    {
        running = false;
        g_rpcBySock.remove(sock.ptr);
        try
            hs_udx_socket_close(sock.ptr);
        catch (Exception)
        {
        }
    }

    /// Send `command` to `to` and wait for the reply (throws on timeout). `internal`
    /// marks a built-in dht-rpc command (FIND_NODE, PING); hyperdht commands
    /// (LOOKUP, ANNOUNCE, PEER_HANDSHAKE) are external — pass internal=false and, when
    /// committing, the token from that node's earlier reply.
    Reply request(Address to, uint command, scope const(ubyte)[] target = null,
        scope const(ubyte)[] value = null, scope const(ubyte)[] token = null,
        bool internal = true, Duration timeout = 2.seconds)
    {
        immutable tid = nextTid++;
        if (nextTid == 0)
            nextTid = 1;

        auto p = new Pending;
        p.ev = createManualEvent();
        pending[tid] = p;
        scope (exit)
            pending.remove(tid);

        auto req = encodeRequest(tid, to, command, target, value, token, null, internal);

        // Resolve once; remember the resolved IP+port so a forged reply from some
        // other source with a guessed tid can't wake this request.
        auto na = resolveHost(to.host);
        na.port = to.port;
        p.expectHost = na.toAddressString();
        p.expectPort = to.port;

        immutable cnt = p.ev.emitCount;
        sendResolved(req, na);
        p.ev.wait(timeout, cnt);
        if (!p.got)
            throw new Exception("dht: request timed out");
        return p.reply;
    }

    private void sendResolved(ubyte[] data, NetworkAddress na)
    {
        auto sreq = new ubyte[](hs_udx_sizeof_socket_send());
        // keep the request block + payload alive past this call (udx references the
        // buffer until the datagram is flushed).
        sendKeep[sendIdx] = sreq;
        sendKeep[(sendIdx + 1) % SEND_RING] = data;
        sendIdx = (sendIdx + 2) % SEND_RING;

        auto b = uv_buf_t(cast(char*) data.ptr, data.length);
        hs_udx_socket_send(sreq.ptr, sock.ptr, &b, 1, cast(const(void)*) na.sockAddr, null);
    }

    /// Send a raw datagram to `to` (used to reply to a request). resolveHost handles
    /// both dotted-quad IPs (immediate) and hostnames (the live bootstrap is
    /// node{1,2,3}.hyperdht.org).
    void send(Address to, ubyte[] datagram)
    {
        auto na = resolveHost(to.host);
        na.port = to.port;
        sendResolved(datagram, na);
    }

    // Called from the udx socket recv callback with one datagram.
    package void onDatagram(ubyte[] got, const(void)* from) nothrow
    {
        if (!running || got.length < 2)
            return;
        // dup: decoded fields slice into the packet, and the recv buffer is reused —
        // the decoded message must own its bytes past this callback.
        if (got[0] == REQUEST_ID)
        {
            if (onRequest is null)
                return;
            RequestPacket req;
            try
                req = decodeRequest(got.dup);
            catch (Exception)
                return;
            onRequest(req, addrFromSockaddr(from));
            return;
        }
        if (got[0] != RESPONSE_ID)
            return;
        Reply r;
        try
            r = decodeReply(got.dup);
        catch (Exception)
            return;
        if (auto pp = r.tid in pending)
        {
            auto p = *pp;
            // Drop a reply whose source isn't the node we sent this tid to.
            auto src = addrFromSockaddr(from);
            if (src.port != p.expectPort || src.host != p.expectHost)
                return;
            p.reply = r;
            p.got = true;
            try
                p.ev.emit();
            catch (Exception)
            {
            }
        }
    }
}
