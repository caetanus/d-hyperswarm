/// A pool of short-lived udx sockets, each on the Rpc's udx instance and each with
/// its own external NAT mapping. hyperdht's holepunch is built on many of these:
/// the NAT sampler pings from a fresh one to observe a per-socket mapping, and the
/// RANDOM side opens up to BIRTHDAY_SOCKETS (256) of them to spray a symmetric NAT.
///
/// Each socket is registered with the Rpc so its dht-rpc replies (>1 byte) reach
/// the Rpc's pending map (the 1-byte HOLEPUNCH beacon demux is layered on later,
/// with the holepuncher). Cooperative single-threaded like the rest of the udx
/// layer, so no lock.
module hyperswarm.dht.socket_pool;

import hyperswarm.dht.rpc : Rpc;
import hyperswarm.udx.udx;

import core.sys.posix.sys.socket : sockaddr, sockaddr_storage, AF_INET;
import core.sys.posix.netinet.in_ : sockaddr_in;
import core.sys.posix.arpa.inet : htons, ntohs;

// udx's socket close is asynchronous: hs_udx_socket_close only STARTS it (uv_close
// on the handles) and the close callback fires later from the loop. The backing
// memory of a socket is therefore kept until this callback, never at release().
private __gshared SocketPool[void*] g_poolOf; // socket ptr -> its pool
extern (C) void poolSockClose(void* s) nothrow
{
    if (auto p = s in g_poolOf)
    {
        auto pool = *p;
        g_poolOf.remove(s);
        pool.acquired.remove(s);
        pool.closing.remove(s);
    }
}

// The facade's fd accessor (uv_fileno). Diagnostic use.
import hyperswarm.udx.facade : __d_hsuv_fileno; // udx::__d_hsuv_fileno — the facade itself, not a C prototype

private enum int UV_EBUSY = -16;

final class SocketPool
{
    private Rpc rpc;
    private ubyte[][void*] acquired; // socket ptr -> its backing memory (kept alive)
    private bool[void*] closing; // close started, callback pending
    private bool[void*] lent; // handed to a Connection (punched hole); released by it

    this(Rpc rpc)
    {
        this.rpc = rpc;
    }

    /// A fresh udx socket bound to an ephemeral port, registered so replies to it
    /// reach the Rpc. Pass the returned ptr to Rpc.request(..., viaSock) to send
    /// from it, or use it to punch. Throws if init/bind fails.
    void* acquire()
    {
        auto mem = new ubyte[](hs_udx_sizeof_socket());
        if (hs_udx_socket_init(rpc.udxPtr, mem.ptr, &poolSockClose) != 0)
            throw new Exception("socket pool: udx socket init failed");
        // Root the backing memory NOW: init linked it into udx, whose close is
        // asynchronous (poolSockClose fires later and frees it). If bind fails
        // below, release() starts that async close against a still-rooted block.
        acquired[mem.ptr] = mem;
        g_poolOf[mem.ptr] = this;
        sockaddr_in b;
        b.sin_family = AF_INET;
        b.sin_addr.s_addr = 0; // INADDR_ANY
        b.sin_port = htons(0); // ephemeral
        if (hs_udx_socket_bind(mem.ptr, cast(sockaddr*)&b, 0) != 0)
        {
            release(mem.ptr); // async close; poolSockClose frees the rooted block
            throw new Exception("socket pool: udx socket bind failed");
        }
        rpc.registerPoolSocket(mem.ptr);
        return mem.ptr;
    }

    /// Unregister and close a socket taken from the pool. Returns false when udx
    /// still has a stream on it (UV_EBUSY): the socket then stays owned — by the
    /// pool, or by the Connection it was lent to — and is closed when that stream
    /// goes away (see lend). The backing memory lives until udx's close callback.
    bool release(void* s) nothrow
    {
        if ((s in acquired) is null || (s in closing) !is null)
            return true; // not ours / already closing
        immutable rc = hs_udx_socket_close(s);
        if (rc == UV_EBUSY)
            return false; // a stream still rides it — its owner closes it later
        rpc.unregisterPoolSocket(s);
        closing[s] = true;
        lent.remove(s);
        return true;
    }

    /// Transfer a punched socket to the connection formed over it: the pool keeps
    /// the memory alive, the beacon sink is dropped, and the socket is closed the
    /// moment the connection's stream is gone (its close callback calls giveBack).
    /// Idempotent per socket.
    void lend(void* s) nothrow
    {
        if ((s in acquired) is null)
            return;
        lent[s] = true;
        rpc.onBeacon(s, null);
    }

    /// The connection over a lent socket is closed: close the socket now that udx
    /// has no stream on it. No-op for a socket that was not lent.
    void giveBack(void* s) nothrow
    {
        if ((s in lent) is null)
            return;
        lent.remove(s);
        release(s);
    }

    /// Release every socket still held (lent ones included: their connections are
    /// expected to be destroyed by then — see Hyperswarm.close).
    void closeAll() nothrow
    {
        foreach (s; acquired.keys) // .keys is a snapshot, so release() may mutate
            release(cast(void*) s);
    }

    /// How many sockets are currently held — open, lent, or closing (until udx's
    /// close callback frees them).
    size_t count() const @safe pure nothrow
    {
        return acquired.length;
    }

    /// How many sockets are open and NOT yet closing.
    size_t openCount() const @safe pure nothrow
    {
        return acquired.length - closing.length;
    }

    /// Whether `s` is a live socket of this pool.
    bool owns(void* s) const nothrow
    {
        return (s in acquired) !is null && (s in closing) is null;
    }

    /// Whether `s` was lent to a connection and is still alive.
    bool isLent(void* s) const nothrow
    {
        return (s in lent) !is null;
    }

    /// The ephemeral port a pool socket was bound to. Used to tell a peer where to
    /// punch (paired with our sampled external host) and to target a loopback peer
    /// in tests. 0 if getsockname fails.
    ushort boundPort(void* s) nothrow
    {
        sockaddr_storage ss;
        int sl = cast(int) ss.sizeof;
        if (hs_udx_socket_getsockname(s, &ss, &sl) != 0)
            return 0;
        return ntohs((cast(sockaddr_in*)&ss).sin_port);
    }

    /// The OS fd backing a pool socket (uv_udp is the first field of udx_socket_t,
    /// so the socket ptr is its uv handle). Diagnostic: to compare against a RAW
    /// getsockname on the fd and catch a cached/stale localAddress on the send path.
    int fileno(void* s) nothrow
    {
        int fd = -1;
        cast(void) __d_hsuv_fileno(s, &fd);
        return fd;
    }
}
