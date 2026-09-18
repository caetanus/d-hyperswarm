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

extern (C) void poolSockClose(void* s) nothrow {}

final class SocketPool
{
    private Rpc rpc;
    private ubyte[][void*] acquired; // socket ptr -> its backing memory (kept alive)

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
        sockaddr_in b;
        b.sin_family = AF_INET;
        b.sin_addr.s_addr = 0; // INADDR_ANY
        b.sin_port = htons(0); // ephemeral
        if (hs_udx_socket_bind(mem.ptr, cast(sockaddr*)&b, 0) != 0)
            throw new Exception("socket pool: udx socket bind failed");
        acquired[mem.ptr] = mem;
        rpc.registerPoolSocket(mem.ptr);
        return mem.ptr;
    }

    /// Unregister and close a socket taken from the pool.
    void release(void* s) nothrow
    {
        rpc.unregisterPoolSocket(s);
        try
            hs_udx_socket_close(s);
        catch (Exception)
        {
        }
        acquired.remove(s);
    }

    /// Release every socket still held.
    void closeAll() nothrow
    {
        foreach (s; acquired.keys) // .keys is a snapshot, so release() may mutate
            release(cast(void*) s);
    }

    /// How many sockets are currently held.
    size_t count() const @safe pure nothrow
    {
        return acquired.length;
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
}
