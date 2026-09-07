/// The D side of the libuv→vibe facade: the `hsuv_*` functions libudx calls.
///
/// libudx's vendored C is amalgamated as one C++ TU in `namespace udx` and
/// compiled against our shim uv.h, which renames every libuv function to `hsuv_*`
/// (symbol isolation — see vendor/libudx-shim/uv.h). Those are the C-ABI symbols
/// this module defines. libudx never calls uv_run: WE drive the callbacks from a
/// vibe fiber (`Loop.run`), so there is one event loop (vibe's), single-threaded.
///
/// Cooperative single-threading is what makes this safe: a libudx callback (recv,
/// timer, send-done) is plain C and never yields, so it runs to completion before
/// any other fiber gets the CPU — libudx never sees its own state half-mutated by
/// another fiber. The reader fiber, the loop runner and send tasks interleave only
/// at their vibe yield points.
///
/// STATUS: loop + timers + buffers + UDP are live; prepare/check, getaddrinfo and
/// interfaces are still stubs (they assert if called). See notes/uv-facade.md.
///
/// Every `hsuv_*` function is `nothrow`: libudx is C and a D exception unwinding
/// into it would be undefined behaviour, so each catches internally and returns a
/// libuv-style negative code on failure.
module hyperswarm.udx.facade;

import core.time : MonoTime, Duration, msecs;
import core.stdc.errno : errno, EAGAIN, EWOULDBLOCK;
import core.sys.posix.sys.socket : sockaddr, socklen_t, msghdr, iovec, sendmsg,
    setsockopt, getsockopt, SOL_SOCKET, SO_SNDBUF, SO_RCVBUF, AF_INET, AF_INET6;
import core.sys.posix.netinet.in_ : sockaddr_in, sockaddr_in6, IPPROTO_IP;
import vibe.core.sync : LocalManualEvent, createManualEvent;
import vibe.core.net : UDPConnection, NetworkAddress, listenUDP;
import vibe.core.core : runTask;

// Linux socket-option constants not always surfaced by druntime imports.
private enum int IP_TTL = 2;
private enum int IPPROTO_IPV6 = 41;
private enum int IPV6_UNICAST_HOPS = 16;
private enum int MSG_DONTWAIT = 0x40;

// libuv error codes we return (mirroring the shim's negative-errno convention).
private enum int UV_EAGAIN = -EAGAIN;
private enum int UV_EINVAL = -22;

// ── C struct layouts (must match vendor/libudx-shim/uv.h) ────────────────────

/// `uv_buf_t { char* base; size_t len; }` — laid out identically to `iovec`.
struct uv_buf_t
{
    char* base;
    size_t len;
}

/// `uv_loop_t { void* data; void* impl; }`. `impl` carries the D `Loop`.
struct uv_loop_t
{
    void* data;
    void* impl;
}

/// The common prefix every uv handle begins with (UV_HANDLE_FIELDS in the shim).
/// libudx only ever touches `.data`; we use `.loop`/`.impl`/`.active`/`.type`.
struct uv_handle_t
{
    void* data;
    uv_loop_t* loop;
    int type;
    int active;
    int closing;
    void* closeCb;
    void* impl;
}

alias uv_timer_t = uv_handle_t;
alias uv_udp_t = uv_handle_t;

/// uv handle type tags (order matches the shim enum).
private enum : int
{
    UV_UNKNOWN_HANDLE = 0,
    UV_HANDLE,
    UV_UDP,
    UV_TIMER,
    UV_PREPARE,
    UV_CHECK
}

private alias CTimerCb = extern (C) void function(uv_handle_t*) nothrow;
private alias CCloseCb = extern (C) void function(uv_handle_t*) nothrow;
private alias CAllocCb = extern (C) void function(uv_handle_t*, size_t, uv_buf_t*) nothrow;
private alias CRecvCb = extern (C) void function(uv_handle_t*, ptrdiff_t, const(uv_buf_t)*, const(sockaddr)*, uint) nothrow;
private alias CSendCb = extern (C) void function(void*, int) nothrow;

// ── helpers ──────────────────────────────────────────────────────────────────

private NetworkAddress toNetworkAddress(const(sockaddr)* sa) nothrow @trusted
{
    // Copy the raw sockaddr bytes through sockAddr (no family precondition);
    // sockAddrInet4/6 assert on family, which a fresh NetworkAddress hasn't set.
    NetworkAddress na;
    immutable len = sockaddrLen(sa);
    (cast(ubyte*) na.sockAddr)[0 .. len] = (cast(const(ubyte)*) sa)[0 .. len];
    return na;
}

private socklen_t sockaddrLen(const(sockaddr)* sa) nothrow @trusted
{
    return sa.sa_family == AF_INET ? sockaddr_in.sizeof : sockaddr_in6.sizeof;
}

// ── the event loop (driven by a vibe fiber) ──────────────────────────────────

private struct TimerState
{
    CTimerCb cb;
    ulong deadline; // absolute ms; meaningful only while `active`
    ulong repeat; // ms between fires; 0 = one-shot
    bool active;
}

private struct PendingClose
{
    uv_handle_t* handle;
    CCloseCb cb;
}

/// Per-UDP-socket state. The vibe UDPConnection carries the socket; a reader
/// fiber turns its blocking recv into libuv's alloc_cb+recv_cb callbacks.
private final class UdpState
{
    Loop loop;
    uv_udp_t* handle;
    UDPConnection conn;
    int family; // 4 or 6, from the bound address
    bool bound;
    bool receiving;
    CAllocCb allocCb;
    CRecvCb recvCb;

    this(Loop l, uv_udp_t* h) nothrow
    {
        loop = l;
        handle = h;
    }

    int fd() nothrow @trusted
    {
        return conn.fd;
    }
}

/// One libuv loop, backed by vibe. libudx registers timers and UDP sockets
/// against it; `run` is the loop-runner a vibe fiber drives.
final class Loop
{
    private uv_loop_t cLoop;
    private ulong nowMs;
    private MonoTime epoch;
    private TimerState[void*] timers; // keyed by the handle pointer
    private UdpState[void*] udps; // keyed by the handle pointer
    private PendingClose[] pendingCloses;
    private LocalManualEvent wake;
    private bool running;

    this() nothrow
    {
        cLoop.impl = cast(void*) this;
        epoch = MonoTime.currTime;
        try
            wake = createManualEvent();
        catch (Exception)
        {
        }
        updateNow();
    }

    /// The `uv_loop_t*` handed to libudx (stable while this Loop is alive).
    void* chandle() nothrow return
    {
        return cast(void*)&cLoop;
    }

    private void updateNow() nothrow
    {
        nowMs = (MonoTime.currTime - epoch).total!"msecs";
    }

    private bool nextDeadline(out ulong next) nothrow
    {
        bool any;
        foreach (ref t; timers)
        {
            if (!t.active)
                continue;
            if (!any || t.deadline < next)
            {
                next = t.deadline;
                any = true;
            }
        }
        return any;
    }

    // Only called from run() (already non-nothrow); the `due` append may allocate.
    private void fireExpired()
    {
        void*[] due;
        foreach (h, ref t; timers)
            if (t.active && t.deadline <= nowMs)
                due ~= cast(void*) h;

        foreach (h; due)
        {
            auto p = h in timers;
            if (p is null || !p.active || p.deadline > nowMs)
                continue;
            auto cb = p.cb;
            if (p.repeat > 0)
                p.deadline = nowMs + p.repeat; // re-arm
            else
            {
                p.active = false;
                (cast(uv_handle_t*) h).active = 0;
            }
            if (cb !is null)
                cb(cast(uv_handle_t*) h);
        }
    }

    private void drainCloses() nothrow
    {
        if (pendingCloses.length == 0)
            return;
        auto cs = pendingCloses;
        pendingCloses = null;
        foreach (c; cs)
            if (c.cb !is null)
                c.cb(c.handle);
    }

    /// Drive the loop until `stop`. Runs on a vibe fiber; may block (and be
    /// interrupted) inside `wake.wait`, which is why this is not `nothrow`.
    void run()
    {
        running = true;
        updateNow();
        while (running)
        {
            fireExpired();
            drainCloses();
            if (!running)
                break;

            immutable cnt = wake.emitCount;
            ulong next;
            if (nextDeadline(next))
            {
                immutable long dms = cast(long) next - cast(long) nowMs;
                if (dms <= 0)
                {
                    updateNow();
                    continue;
                }
                wake.wait(dms.msecs, cnt);
            }
            else
                wake.wait(cnt);
            updateNow();
        }
    }

    void stop() nothrow
    {
        running = false;
        poke();
    }

    private void poke() nothrow
    {
        try
            wake.emit();
        catch (Exception)
        {
        }
    }

    // ── timer ops ────────────────────────────────────────────────────────────
    private void registerTimer(void* h) nothrow
    {
        timers[h] = TimerState.init;
    }

    private void startTimer(void* h, CTimerCb cb, ulong timeout, ulong repeat) nothrow
    {
        auto p = h in timers;
        if (p is null)
        {
            registerTimer(h);
            p = h in timers;
        }
        p.cb = cb;
        p.deadline = nowMs + timeout;
        p.repeat = repeat;
        p.active = true;
        poke();
    }

    private void stopTimer(void* h) nothrow
    {
        if (auto p = h in timers)
            p.active = false;
        poke();
    }

    // ── udp ops ──────────────────────────────────────────────────────────────
    private void registerUdp(void* h, UdpState st) nothrow
    {
        udps[h] = st;
    }

    // ── close ────────────────────────────────────────────────────────────────
    private void closeHandle(uv_handle_t* h, CCloseCb cb) nothrow
    {
        auto key = cast(void*) h;
        if (auto st = key in udps)
        {
            st.receiving = false;
            try
                st.conn.close();
            catch (Exception)
            {
            }
            udps.remove(key);
        }
        timers.remove(key);
        h.active = 0;
        h.closing = 1;
        if (cb !is null)
            pendingCloses ~= PendingClose(h, cb);
        poke();
    }
}

private Loop loopOf(void* loopPtr) nothrow
{
    return cast(Loop)(cast(uv_loop_t*) loopPtr).impl;
}

private UdpState udpOf(uv_handle_t* h) nothrow
{
    return cast(UdpState) h.impl;
}

// ── the hsuv_* facade (C ABI, nothrow) ───────────────────────────────────────

extern (C):

private noreturn nyi(string what) nothrow
{
    assert(0, what);
}

// ── loop / time ──────────────────────────────────────────────────────────────
ulong hsuv_now(const(void)* loop) nothrow
{
    return loopOf(cast(void*) loop).nowMs;
}

ulong hsuv_hrtime() nothrow
{
    immutable t = MonoTime.currTime.ticks;
    immutable freq = MonoTime.ticksPerSecond;
    return cast(ulong)(t / freq) * 1_000_000_000UL
        + cast(ulong)((t % freq) * 1_000_000_000UL / freq);
}

// ── buffers ──────────────────────────────────────────────────────────────────
uv_buf_t hsuv_buf_init(char* base, uint len) nothrow
{
    return uv_buf_t(base, len);
}

// ── handles ──────────────────────────────────────────────────────────────────
void hsuv_close(void* handle, void* close_cb) nothrow
{
    auto h = cast(uv_handle_t*) handle;
    if (h.loop !is null)
        loopOf(cast(void*) h.loop).closeHandle(h, cast(CCloseCb) close_cb);
}

int hsuv_is_active(const(void)* handle) nothrow
{
    return (cast(uv_handle_t*) handle).active;
}

int hsuv_fileno(const(void)* handle, int* fd) nothrow
{
    auto st = udpOf(cast(uv_handle_t*) handle);
    if (st is null || !st.bound)
        return UV_EINVAL;
    *fd = st.fd;
    return 0;
}

int hsuv_recv_buffer_size(void* handle, int* value) nothrow
{
    return bufferSize(cast(uv_handle_t*) handle, SO_RCVBUF, value);
}

int hsuv_send_buffer_size(void* handle, int* value) nothrow
{
    return bufferSize(cast(uv_handle_t*) handle, SO_SNDBUF, value);
}

// libuv semantics: *value == 0 → get current into *value; else set it. Linux
// doubles the SO_*BUF value it stores, matching what libuv reports.
private int bufferSize(uv_handle_t* h, int opt, int* value) nothrow @trusted
{
    auto st = udpOf(h);
    if (st is null || !st.bound)
        return UV_EINVAL;
    if (*value == 0)
    {
        socklen_t len = int.sizeof;
        if (getsockopt(st.fd, SOL_SOCKET, opt, value, &len) != 0)
            return -errno;
    }
    else if (setsockopt(st.fd, SOL_SOCKET, opt, value, int.sizeof) != 0)
        return -errno;
    return 0;
}

// ── timers ───────────────────────────────────────────────────────────────────
int hsuv_timer_init(void* loop, void* handle) nothrow
{
    auto h = cast(uv_handle_t*) handle;
    h.loop = cast(uv_loop_t*) loop;
    h.type = UV_TIMER;
    h.active = 0;
    h.closing = 0;
    loopOf(loop).registerTimer(handle);
    return 0;
}

int hsuv_timer_start(void* handle, void* cb, ulong timeout, ulong repeat) nothrow
{
    auto h = cast(uv_handle_t*) handle;
    h.active = 1;
    loopOf(cast(void*) h.loop).startTimer(handle, cast(CTimerCb) cb, timeout, repeat);
    return 0;
}

int hsuv_timer_stop(void* handle) nothrow
{
    auto h = cast(uv_handle_t*) handle;
    h.active = 0;
    if (h.loop !is null)
        loopOf(cast(void*) h.loop).stopTimer(handle);
    return 0;
}

// ── UDP ──────────────────────────────────────────────────────────────────────
int hsuv_udp_init(void* loop, void* handle) nothrow
{
    auto h = cast(uv_handle_t*) handle;
    h.loop = cast(uv_loop_t*) loop;
    h.type = UV_UDP;
    h.active = 0;
    h.closing = 0;
    auto lp = loopOf(loop);
    auto st = new UdpState(lp, h);
    h.impl = cast(void*) st;
    lp.registerUdp(handle, st);
    return 0;
}

int hsuv_udp_bind(void* handle, const(void)* addr, uint flags) nothrow
{
    auto h = cast(uv_handle_t*) handle;
    auto st = udpOf(h);
    if (st is null)
        return UV_EINVAL;
    auto sa = cast(const(sockaddr)*) addr;
    try
    {
        auto na = toNetworkAddress(sa);
        st.conn = listenUDP(na);
        st.family = sa.sa_family == AF_INET ? 4 : 6;
        st.bound = true;
        h.active = 1;
    }
    catch (Exception)
        return UV_EINVAL;
    return 0;
}

int hsuv_udp_getsockname(const(void)* handle, void* name, int* namelen) nothrow
{
    auto st = udpOf(cast(uv_handle_t*) handle);
    if (st is null || !st.bound)
        return UV_EINVAL;
    try
    {
        auto na = st.conn.localAddress;
        immutable len = na.sockAddrLen;
        (cast(ubyte*) name)[0 .. len] = (cast(ubyte*) na.sockAddr)[0 .. len];
        *namelen = len;
    }
    catch (Exception)
        return UV_EINVAL;
    return 0;
}

int hsuv_udp_recv_start(void* handle, void* alloc_cb, void* recv_cb) nothrow
{
    auto h = cast(uv_handle_t*) handle;
    auto st = udpOf(h);
    if (st is null || !st.bound)
        return UV_EINVAL;
    st.allocCb = cast(CAllocCb) alloc_cb;
    st.recvCb = cast(CRecvCb) recv_cb;
    if (st.receiving)
        return 0;
    st.receiving = true;
    try
        runTask(&readerLoop, st);
    catch (Exception)
        return UV_EINVAL;
    return 0;
}

// The bridge: turn vibe's blocking recv into libuv's alloc_cb + recv_cb. Runs on
// its own fiber; the callbacks it invokes are libudx C and never yield, so they
// are atomic w.r.t. the loop runner and timers.
private void readerLoop(UdpState st) nothrow
{
    while (st.receiving)
    {
        uv_buf_t buf;
        st.allocCb(st.handle, 65536, &buf);
        NetworkAddress peer;
        ubyte[] got;
        try
            got = st.conn.recv(cast(ubyte[]) buf.base[0 .. buf.len], &peer);
        catch (Exception)
            break; // interrupted or closed
        if (!st.receiving)
            break;
        if (got is null)
            continue;
        st.recvCb(st.handle, cast(ptrdiff_t) got.length, &buf,
            cast(const(sockaddr)*) peer.sockAddr, 0);
    }
}

int hsuv_udp_send(void* req, void* handle, const(uv_buf_t)* bufs, uint nbufs, const(void)* addr, void* send_cb) nothrow
{
    auto st = udpOf(cast(uv_handle_t*) handle);
    if (st is null || !st.bound)
        return UV_EINVAL;
    auto cb = cast(CSendCb) send_cb;
    try
    {
        // Coalesce the buffers and hand the send to a fiber, which lets vibe wait
        // for writability rather than dropping on a full socket buffer. The
        // send_cb fires from that fiber (cooperative — atomic w.r.t. libudx).
        size_t total;
        foreach (i; 0 .. nbufs)
            total += bufs[i].len;
        auto data = new ubyte[total];
        size_t off;
        foreach (i; 0 .. nbufs)
        {
            data[off .. off + bufs[i].len] = cast(ubyte[]) bufs[i].base[0 .. bufs[i].len];
            off += bufs[i].len;
        }
        auto peer = toNetworkAddress(cast(const(sockaddr)*) addr);
        auto conn = st.conn;
        runTask(() nothrow {
            int status = 0;
            try
                conn.send(data, &peer);
            catch (Exception)
                status = -1;
            if (cb !is null)
                cb(req, status);
        });
    }
    catch (Exception)
        return UV_EINVAL;
    return 0;
}

int hsuv_udp_try_send(void* handle, const(uv_buf_t)* bufs, uint nbufs, const(void)* addr) nothrow @trusted
{
    auto st = udpOf(cast(uv_handle_t*) handle);
    if (st is null || !st.bound)
        return UV_EINVAL;
    auto sa = cast(const(sockaddr)*) addr;
    msghdr msg;
    msg.msg_name = cast(void*) sa;
    msg.msg_namelen = sockaddrLen(sa);
    msg.msg_iov = cast(iovec*) bufs; // uv_buf_t and iovec share layout
    msg.msg_iovlen = nbufs;
    immutable n = sendmsg(st.fd, &msg, MSG_DONTWAIT);
    if (n < 0)
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? UV_EAGAIN : -errno;
    return cast(int) n;
}

int hsuv_udp_set_ttl(void* handle, int ttl) nothrow @trusted
{
    auto st = udpOf(cast(uv_handle_t*) handle);
    if (st is null || !st.bound)
        return UV_EINVAL;
    int r;
    if (st.family == 6)
        r = setsockopt(st.fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, int.sizeof);
    else
        r = setsockopt(st.fd, IPPROTO_IP, IP_TTL, &ttl, int.sizeof);
    return r == 0 ? 0 : -errno;
}

int hsuv_udp_set_multicast_loop(void* handle, int on) nothrow { return 0; }
int hsuv_udp_set_multicast_interface(void* handle, const(char)* interface_addr) nothrow { return 0; }
int hsuv_udp_set_membership(void* handle, const(char)* multicast_addr, const(char)* interface_addr, int membership) nothrow { return 0; }
int hsuv_udp_set_source_membership(void* handle, const(char)* multicast_addr, const(char)* interface_addr, const(char)* source_addr, int membership) nothrow { return 0; }

// ── prepare / check (loop-phase hooks) ───────────────────────────────────────
int hsuv_prepare_init(void* loop, void* prepare) nothrow { nyi("uv_prepare_init"); }
int hsuv_prepare_start(void* prepare, void* cb) nothrow { nyi("uv_prepare_start"); }
int hsuv_prepare_stop(void* prepare) nothrow { nyi("uv_prepare_stop"); }
int hsuv_check_init(void* loop, void* check) nothrow { nyi("uv_check_init"); }
int hsuv_check_start(void* check, void* cb) nothrow { nyi("uv_check_start"); }
int hsuv_check_stop(void* check) nothrow { nyi("uv_check_stop"); }

// ── DNS ──────────────────────────────────────────────────────────────────────
int hsuv_getaddrinfo(void* loop, void* req, void* cb, const(char)* node, const(char)* service, const(void)* hints) nothrow { nyi("uv_getaddrinfo"); }
void hsuv_freeaddrinfo(void* ai) nothrow { nyi("uv_freeaddrinfo"); }

// ── interfaces ───────────────────────────────────────────────────────────────
int hsuv_interface_addresses(void* addresses, int* count) nothrow { nyi("uv_interface_addresses"); }
void hsuv_free_interface_addresses(void* addresses, int count) nothrow { nyi("uv_free_interface_addresses"); }

// ── misc ─────────────────────────────────────────────────────────────────────
const(char)* hsuv_strerror(int err) nothrow { nyi("uv_strerror"); }
