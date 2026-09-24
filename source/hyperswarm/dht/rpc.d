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
import hyperswarm.udx.facade : insideUdxCallback, udxCallbacksActive;
import hyperswarm.udx.facade : Loop, uv_buf_t;
import vibe.core.sync : LocalManualEvent, createManualEvent;
import vibe.core.core : runTask, sleep;
import vibe.core.task : Task;
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
        r.onDatagram(cast(ubyte[]) buf.base[0 .. len], from, socket);
}

package Address addrFromSockaddr(const(void)* sa) nothrow
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

// udx keeps the request block and the payload pointers of a send until it has
// left the socket (queued behind a full buffer, or in the specific-TTL queue), so
// both stay rooted here until udx's send callback says it is done — for every
// send, not a fixed ring that a 256-socket birthday burst could lap.
private __gshared ubyte[][][void*] g_sendKeep; // request ptr -> [request block, payload]

extern (C) void hsSendDone(void* req, int status) nothrow
{
    g_sendKeep.remove(req);
}

// Root a send's memory; returns the request block pointer to pass to udx.
private void* keepSend(ubyte[] sreq, ubyte[] data) nothrow
{
    g_sendKeep[sreq.ptr] = [sreq, data];
    return sreq.ptr;
}

// A send udx refused outright (negative return) never calls back: unroot it.
private void sendFailed(void* req) nothrow
{
    g_sendKeep.remove(req);
}

/// Sends still rooted, i.e. not yet confirmed sent by udx (diagnostic / tests).
size_t rpcSendsInFlight() nothrow
{
    return g_sendKeep.length;
}

// Wire diagnostic (PW_HS_TRACE=1): log every rpc request's destination and every
// datagram that arrives at the socket, so a lost-reply can be split into "reply
// never arrives" (send goes to the wrong place / reply can't return) vs "arrives
// but is dropped" (source-address or tid mismatch). Off unless the env is set.
__gshared bool g_hsTrace; // PW_HS_TRACE=1: wire-level diagnostics (also read by connect.d)
shared static this() @trusted nothrow
{
    try
    {
        import std.process : environment;
        g_hsTrace = environment.get("PW_HS_TRACE", "").length != 0;
    }
    catch (Exception)
    {
    }
}

final class Rpc
{
    Loop loop;
    private Task loopTask; // the loop runner, joined by close() so no fiber leaks
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

    // Our own address as other nodes report it (the reply `to` field): a majority
    // vote across responders, so we advertise a reachable address rather than a
    // hard-coded loopback. host is empty until we've heard from a node.
    private uint[string] _selfVotes;
    private Address _remoteAddr;

    // Per-pool-socket sink for 1-byte HOLEPUNCH beacons (installed by the
    // holepuncher via onBeacon). Empty on the main socket / plain rpc use.
    private void delegate(Address from) nothrow[void*] beaconCb;

    /// Diagnostic tap: every datagram delivered (any socket, any size), before
    /// demux. Null in production; a harness uses it to prove whether a packet
    /// physically arrived at the socket vs was lost in transit.
    void delegate(size_t len, Address from, void* viaSock) nothrow onRecvTrace;

    this(ushort bindPort = 0)
    {
        loop = new Loop();
        loopTask = runTask(() nothrow { try loop.run(); catch (Exception) {} });

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

        g_rpcBySock[sock.ptr] = this;
        running = true;
        hs_udx_socket_recv_start(sock.ptr, &hsRpcRecv);
    }

    ushort localPort()
    {
        return _localPort;
    }

    /// Our address as the network reports it (majority of reply `to` fields), or an
    /// Address with an empty host if no node has told us yet.
    Address remoteAddress()
    {
        return _remoteAddr;
    }

    // Fold a responder's view of our address into the running majority vote.
    private void recordSelf(Address to) nothrow
    {
        if (to.host.length == 0 || to.port == 0)
            return;
        try
        {
            immutable key = format("%s:%d", to.host, to.port);
            immutable n = (_selfVotes.get(key, 0) + 1);
            _selfVotes[key] = n;
            immutable best = _remoteAddr.host.length
                ? _selfVotes.get(format("%s:%d", _remoteAddr.host, _remoteAddr.port), 0) : 0;
            if (n >= best)
                _remoteAddr = to;
        }
        catch (Exception)
        {
        }
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

    /// Register a pool socket (created on udxPtr) so its dht-rpc replies route to
    /// this Rpc's pending map, and start receiving on it. The NAT sampler and the
    /// holepuncher send from these to observe a per-socket external mapping.
    package void registerPoolSocket(void* s) nothrow
    {
        g_rpcBySock[s] = this;
        hs_udx_socket_recv_start(s, &hsRpcRecv);
    }

    package void unregisterPoolSocket(void* s) nothrow
    {
        g_rpcBySock.remove(s);
        beaconCb.remove(s);
    }

    /// Install the holepunch-beacon sink for a pool socket. A 1-byte datagram on
    /// that socket (the HOLEPUNCH `[0x00]`) is delivered here instead of being
    /// parsed as dht-rpc; anything >=2 bytes still goes to the rpc path. Passing
    /// null clears it.
    package void onBeacon(void* s, void delegate(Address from) nothrow cb) nothrow
    {
        if (cb is null)
            beaconCb.remove(s);
        else
            beaconCb[s] = cb;
    }

    // udx binds every socket at UDX_DEFAULT_TTL, so a plain send already carries it.
    private enum int UDX_DEFAULT_TTL = 64;

    /// Send the 1-byte HOLEPUNCH beacon `[0x00]` to `to` from `viaSock` at the given
    /// UDP TTL: HOLEPUNCH_TTL (5) for a punch probe that must open our NAT without
    /// yet reaching the peer, DEFAULT_TTL (64) once we want it to land. Never throws
    /// — the holepuncher fires these from background fibers where a send must not
    /// abort the round (matches holepuncher.js's "never fails").
    package void sendBeacon(void* viaSock, Address to, int ttl) nothrow
    {
        try
        {
            auto na = resolveHost(to.host);
            na.port = to.port;
            auto sreq = new ubyte[](hs_udx_sizeof_socket_send());
            auto data = [cast(ubyte) 0];
            auto req = keepSend(sreq, data); // rooted until udx\'s send callback
            auto b = uv_buf_t(cast(char*) data.ptr, data.length);
            // TTL 64 is udx's own socket default, so a plain send already carries it —
            // and it avoids udx_socket_send_ttl's specific-ttl-send-queue machinery,
            // which on a real port-preserving NAT was observed egressing the beacon
            // from a stray socket instead of the holder (the rig punch bug: getsockname
            // said the holder, the datagram left a third port). Only the low priming
            // TTL (5) needs the per-packet override.
            immutable rc = ttl == UDX_DEFAULT_TTL
                ? hs_udx_socket_send(req, viaSock, &b, 1, cast(const(void)*) na.sockAddr, &hsSendDone)
                : hs_udx_socket_send_ttl(req, viaSock, &b, 1, cast(const(void)*) na.sockAddr, ttl, &hsSendDone);
            if (rc < 0)
                sendFailed(req);
        }
        catch (Exception)
        {
        }
    }

    /// Diagnostic: send an arbitrary datagram from a specific socket (a pool holder)
    /// to `to`. The rig harness uses it to test whether a LARGER UDP packet crosses a
    /// NAT where the 1-byte beacon does not (carrier CGNATs sometimes drop tiny
    /// datagrams). Never throws. Not part of the holepunch wire.
    void sendRawFrom(void* viaSock, Address to, scope const(ubyte)[] data) nothrow
    {
        try
        {
            auto na = resolveHost(to.host);
            na.port = to.port;
            auto sreq = new ubyte[](hs_udx_sizeof_socket_send());
            auto buf = data.dup;
            auto req = keepSend(sreq, buf); // rooted until udx\'s send callback
            auto b = uv_buf_t(cast(char*) buf.ptr, buf.length);
            if (hs_udx_socket_send(req, viaSock, &b, 1, cast(const(void)*) na.sockAddr, &hsSendDone) < 0)
                sendFailed(req);
        }
        catch (Exception)
        {
        }
    }

    /// Whether a close has fully settled: the shutdown sequence finished and the loop
    /// runner returned. A close requested from a callback context returns before that
    /// (see close()); wait on this from another fiber before leaving the event loop.
    /// `closeLeftovers` then says whether anything could not be torn down.
    bool closeSettled() nothrow
    {
        if (shutdownTask != Task.init && shutdownTask.running)
            return false;
        return loopTask == Task.init || !loopTask.running;
    }

    /// After closeSettled: whether a socket or handle close could not be completed
    /// (the socket stayed busy, or a handle close never settled) — a leak to report.
    bool closeLeftovers() nothrow
    {
        return socketCloseRc < 0 || !extrasClosed || loop.closesPending();
    }

    /// Run on each close retry; returns whether everything it owns is closed. The Dht
    /// retries its pool sockets here: one still carrying a stream when first released
    /// (its DESTROY maybe blocked behind a send) closes once the stream is gone — and
    /// while it is open, shutdown keeps retrying and cancels blocked sends.
    bool delegate() nothrow onCloseRetry;
    private bool extrasClosed = true;

    private Task shutdownTask;
    private int socketCloseRc = -16;
    private bool closing;

    void close()
    {
        if (closing)
            return;
        closing = true;
        running = false;
        g_rpcBySock.remove(sock.ptr);
        // From inside the loop fiber, a udx I/O fiber, or a udx callback on any task
        // (a stream's onClose -> application -> Hyperswarm.close), the shutdown must not
        // block here: the loop cannot settle the socket until this very frame unwinds
        // (and joining the loop from itself asserts). Hand the whole sequence to its own
        // task instead; the caller returns at once and can wait on closeSettled().
        if (loopTask != Task.init && (Task.getThis() == loopTask || insideUdxCallback()))
        {
            try
            {
                shutdownTask = runTask(&shutdown);
                return;
            }
            catch (Exception)
            {
                loop.stop(); // cannot spawn: at least let the runner wind down
                return;
            }
        }
        shutdown();
    }

    // Close the dht socket, let the loop fire the async close callbacks (udx's uv_close
    // is asynchronous), then stop the loop and JOIN its runner, so a closed DHT leaves no
    // fiber and no half-torn-down udx handle behind. Never runs on the loop task or inside
    // a udx callback (close() hands it off from there).
    private void shutdown() nothrow
    {
        import core.time : msecs;
        // A close begun inside a stream close callback: libudx queues that stream's
        // finalizer handles only once the callback returns (it may yield first). Let
        // every such frame unwind before the loop can be stopped under it.
        for (int i = 0; i < 2000 && udxCallbacksActive(); i++)
            try
                sleep(5.msecs);
            catch (Exception)
            {
            }
        // UV_EBUSY means a stream still rode the socket when we asked (its DESTROY
        // queued behind send backpressure); keep the loop running and retry, so the
        // socket is really torn down rather than abandoned. After a short grace, cancel
        // the blocked sends (loop-wide) so those destroys complete.
        try
            socketCloseRc = hs_udx_socket_close(sock.ptr);
        catch (Exception)
        {
        }
        bool aborted;
        extrasClosed = onCloseRetry is null || onCloseRetry();
        for (int i = 0; i < 400 && (socketCloseRc < 0 || !extrasClosed); i++)
        {
            try
                sleep(5.msecs);
            catch (Exception)
            {
            }
            if (onCloseRetry !is null)
                extrasClosed = onCloseRetry();
            if (socketCloseRc < 0)
                try
                    socketCloseRc = hs_udx_socket_close(sock.ptr);
                catch (Exception)
                {
                }
            if ((socketCloseRc < 0 || !extrasClosed) && !aborted && i >= 10)
            {
                loop.abortSends();
                aborted = true;
            }
        }
        for (int i = 0; i < 400 && loop.closesPending(); i++)
            try
                sleep(5.msecs);
            catch (Exception)
            {
            }
        loop.stop();
        // joinUninterruptible: an interrupt during shutdown must not return before the
        // loop runner has actually terminated.
        if (loopTask != Task.init && loopTask.running)
            loopTask.joinUninterruptible();
    }

    /// Send `command` to `to` and wait for the reply (throws on timeout). `internal`
    /// marks a built-in dht-rpc command (FIND_NODE, PING); hyperdht commands
    /// (LOOKUP, ANNOUNCE, PEER_HANDSHAKE) are external — pass internal=false and, when
    /// committing, the token from that node's earlier reply.
    Reply request(Address to, uint command, scope const(ubyte)[] target = null,
        scope const(ubyte)[] value = null, scope const(ubyte)[] token = null,
        bool internal = true, Duration timeout = 2.seconds, void* viaSock = null)
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

        if (g_hsTrace)
        {
            import core.stdc.stdio : fprintf, stderr;

            fprintf(stderr, "HSTRACE send tid=%u cmd=%u to=%.*s:%u via=%s\n",
                tid, command, cast(int) p.expectHost.length, p.expectHost.ptr,
                to.port, viaSock is null ? "main".ptr : "pool".ptr);
        }
        immutable cnt = p.ev.emitCount;
        sendResolved(req, na, viaSock is null ? sock.ptr : viaSock);
        p.ev.wait(timeout, cnt);
        if (!p.got)
            throw new Exception("dht: request timed out");
        return p.reply;
    }

    private void sendResolved(ubyte[] data, NetworkAddress na, void* viaSock)
    {
        auto sreq = new ubyte[](hs_udx_sizeof_socket_send());
        auto req = keepSend(sreq, data); // rooted until udx\'s send callback

        auto b = uv_buf_t(cast(char*) data.ptr, data.length);
        if (hs_udx_socket_send(req, viaSock, &b, 1, cast(const(void)*) na.sockAddr, &hsSendDone) < 0)
            sendFailed(req);
    }

    /// Send a raw datagram to `to` (used to reply to a request). resolveHost handles
    /// both dotted-quad IPs (immediate) and hostnames (the live bootstrap is
    /// node{1,2,3}.hyperdht.org).
    void send(Address to, ubyte[] datagram)
    {
        auto na = resolveHost(to.host);
        na.port = to.port;
        sendResolved(datagram, na, sock.ptr);
    }

    // Called from the udx socket recv callback with one datagram.
    package void onDatagram(ubyte[] got, const(void)* from, void* viaSock) nothrow
    {
        if (!running)
            return;
        if (g_hsTrace)
        {
            import core.stdc.stdio : fprintf, stderr;

            auto fa = addrFromSockaddr(from);
            fprintf(stderr, "HSTRACE recv len=%zu from=%.*s:%u first=0x%02x\n",
                got.length, cast(int) fa.host.length, fa.host.ptr, fa.port,
                got.length ? got[0] : 0);
        }
        // Diagnostic: every datagram delivered to this Rpc, ANY size, before demux —
        // so a harness can see raw arrivals independent of beacon/rpc routing (the
        // traversal-vs-recv fork on a real NAT). Null in production.
        if (onRecvTrace !is null)
            onRecvTrace(got.length, addrFromSockaddr(from), viaSock);
        // 1-byte datagram = HOLEPUNCH beacon. Demux to this socket's puncher sink
        // (if any) rather than the dht-rpc parser.
        if (got.length == 1)
        {
            if (auto cb = viaSock in beaconCb)
                (*cb)(addrFromSockaddr(from));
            return;
        }
        if (got.length < 2)
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
            // Only the main socket's mapping is our advertised self-address; a
            // pool socket's `to` is a per-socket sample the caller reads off the
            // returned reply (the NAT sampler), and must not pollute _remoteAddr.
            if (viaSock == sock.ptr)
                recordSelf(r.to); // a verified node's view of our address
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
