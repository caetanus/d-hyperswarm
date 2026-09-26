/// The D side of the libuv→vibe facade: the `__d_hsuv_*` functions libudx calls.
///
/// libudx's vendored C is amalgamated as one C++ TU in `namespace udx` and
/// compiled against our shim uv.h, which renames every libuv function to `__d_hsuv_*`
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
/// Every `__d_hsuv_*` function is `nothrow`: libudx is C and a D exception unwinding
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
import vibe.core.task : Task;

// Diagnostic: HS_UDX_SEND_TRACE=1 logs which send path fires and the real fd, to
// catch a beacon leaving a different socket than the holder (holepunch rig).
import core.stdc.stdio : fprintf, stderr;
private __gshared int g_sendTrace = -1;
private bool sendTraceOn() nothrow @trusted
{
    if (g_sendTrace < 0)
    {
        import core.stdc.stdlib : getenv;

        g_sendTrace = getenv("HS_UDX_SEND_TRACE") !is null ? 1 : 0;
    }
    return g_sendTrace == 1;
}

// Linux socket-option constants not always surfaced by druntime imports.
private enum int IP_TTL = 2;
private enum int IPPROTO_IPV6 = 41;
private enum int IPV6_UNICAST_HOPS = 16;
private enum int MSG_DONTWAIT = 0x40;

// libuv error codes we return (mirroring the shim's negative-errno convention).
private enum int UV_EAGAIN = -EAGAIN;
private enum int UV_EINVAL = -22;
private enum int UV_ECANCELED = -125;

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
private alias CPhaseCb = extern (C) void function(uv_handle_t*) nothrow; // prepare/check
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
    UdpState udp; // set for a UDP handle: its send queue is settled before cb runs
}

/// A prepare or check handle: its callback runs each loop iteration while active
/// (prepare before the poll/wait, check after).
private struct PhaseHook
{
    CPhaseCb cb;
    bool active;
}

/// Per-UDP-socket state. The vibe UDPConnection carries the socket; a reader
/// fiber turns its blocking recv into libuv's alloc_cb+recv_cb callbacks.
// One queued libuv-style send: data already coalesced, completion callback kept.
private struct PendingSend
{
    void* req;
    ubyte[] data;
    NetworkAddress peer;
    CSendCb cb;
}

private final class UdpState
{
    Loop loop;
    uv_udp_t* handle;
    UDPConnection conn;
    // uv_udp_send semantics: sends are QUEUED and completed in order by ONE drain
    // fiber per socket. A vibe UDPConnection tolerates a single send in flight —
    // eventcore keeps one write callback per socket — so a burst that fills the
    // kernel buffer must wait its turn here, never fan out into parallel sends.
    PendingSend[] sendQueue;
    bool draining;
    bool closing; // close started: no new sends; the queue is cancelled before the close cb
    bool aborting; // shutdown: sends are cancelled (UV_ECANCELED) instead of waited for
    int family; // 4 or 6, from the bound address
    bool bound;
    bool receiving;
    // The reader fiber (parked in conn.recv between datagrams). Kept so a close can
    // interrupt it: closing the UDPConnection alone does not wake a parked recv, which
    // then holds the socket's eventcore handle — the FD stays bound, the fiber lives on.
    Task reader;
    Task drainer; // the send-drain fiber (a close interrupts it if it is blocked in send)
    CAllocCb allocCb;

    /// Whether the reader fiber is still alive (Task.running asserts on a null handle).
    bool readerAlive() nothrow
    {
        return reader != Task.init && reader.running;
    }
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
    private PhaseHook[void*] prepares; // run before the poll
    private PhaseHook[void*] checks; // run after the poll
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
        try
        {
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
        }
        catch (Exception)
        {
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
        {
            if (c.udp !is null)
            {
                if (c.udp.draining)
                {
                    // The drain fiber is inside its current send; it stops at the closing
                    // flag right after. If that send is blocked (the socket buffer full),
                    // interrupt it: uv_close cancels in-flight requests, and its callback
                    // then completes with UV_ECANCELED. Settle this handle when it pokes.
                    if (c.udp.drainer != Task.init && c.udp.drainer.running && Task.getThis() != c.udp.drainer)
                        c.udp.drainer.interrupt();
                    pendingCloses ~= c;
                    continue;
                }
                if (c.udp.readerAlive())
                {
                    // Parked in recv: wake it with an interrupt (its recv throws, the
                    // loop exits). This runs on the loop task — never inside a C
                    // callback and never on the reader itself (a task cannot interrupt
                    // itself). A reader that started this close from its own recv
                    // callback just returns: `receiving` is already false.
                    if (Task.getThis() != c.udp.reader)
                        c.udp.reader.interrupt();
                    pendingCloses ~= c;
                    continue;
                }
                cancelSends(c.udp);
                // Only now, with no fiber left on the socket, release it.
                try
                    c.udp.conn.close();
                catch (Exception)
                {
                }
            }
            if (c.cb !is null)
                c.cb(c.handle);
        }
        // A close requeued above waits for a fiber (the drain fiber finishing its send,
        // the interrupted reader unwinding); each pokes the loop as it exits. Poking
        // here instead would make the next wait return at once — a busy spin that
        // starves exactly the fiber being waited for.
    }

    /// Whether any handle close is still waiting to run its callback (tests).
    bool closesPending() const nothrow @safe
    {
        return pendingCloses.length != 0;
    }

    // Run active prepare/check hooks. Collect first: a hook may start/stop hooks.
    // Only called from run() (already non-nothrow); the `due` append may allocate.
    private void runHooks(ref PhaseHook[void*] hooks)
    {
        if (hooks.length == 0)
            return;
        void*[] due;
        foreach (h, ref hook; hooks)
            if (hook.active)
                due ~= cast(void*) h;
        foreach (h; due)
        {
            auto p = h in hooks;
            if (p is null || !p.active)
                continue;
            if (p.cb !is null)
                p.cb(cast(uv_handle_t*) h);
        }
    }

    /// Drive the loop until `stop`. Runs on a vibe fiber; may block (and be
    /// interrupted) inside `wake.wait`, which is why this is not `nothrow`.
    void run()
    {
        running = true;
        updateNow();
        while (running)
        {
            // Snapshot the wake counter BEFORE this iteration's callbacks: a poke()
            // they issue (drainCloses asking for another pass while a closing socket's
            // fibers unwind, a timer (re)started, a hook armed) must end the wait below
            // at once. Snapshotting after them swallowed that poke and parked the loop
            // until the next timer — a deferred socket close then took a timer period.
            immutable cnt = wake.emitCount;
            fireExpired();
            drainCloses();
            if (!running)
                break;

            runHooks(prepares); // libuv "prepare" phase — before the poll
            if (!running)
                break;

            ulong next;
            if (nextDeadline(next))
            {
                immutable long dms = cast(long) next - cast(long) nowMs;
                if (dms > 0)
                    wake.wait(dms.msecs, cnt);
            }
            else
                wake.wait(cnt);
            updateNow();

            runHooks(checks); // libuv "check" phase — after the poll
        }
        // Stopped — but handle closes may still be in flight (a socket closed from a
        // callback just before stop(): its reader must be woken and its fd released,
        // and libudx waits for the close callback). Settle them before the runner
        // returns; the short waits let the interrupted reader/drain fibers unwind.
        for (int i = 0; i < 400 && pendingCloses.length; i++)
        {
            drainCloses();
            if (pendingCloses.length == 0)
                break;
            immutable cnt = wake.emitCount;
            wake.wait(5.msecs, cnt);
        }
    }

    /// Shutdown: cancel every send still queued or blocked on a full socket buffer, on
    /// every socket of this loop. A stream's DESTROY packet stuck behind a blocked send
    /// keeps the stream linked to its socket (the socket close says UV_EBUSY and never
    /// even starts); cancelling completes those sends so the streams can finish closing.
    void abortSends() nothrow
    {
        foreach (udp; udps)
        {
            udp.aborting = true;
            if (udp.draining && udp.drainer != Task.init && udp.drainer.running && Task.getThis() != udp.drainer)
                udp.drainer.interrupt();
            else if (!udp.draining)
                cancelSends(udp);
        }
        poke();
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
        // the clock the deadline counts from, fresh: libudx starts timers from the UDP reader
        // task too, outside the loop's iterations (where nowMs is refreshed), and a stale
        // nowMs made a short timer (the 2 ms delayed ACK) expire on arrival
        updateNow();
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

    // ── prepare / check ops ──────────────────────────────────────────────────
    private void registerHook(ref PhaseHook[void*] hooks, void* h) nothrow
    {
        hooks[h] = PhaseHook.init;
    }

    private void startHook(ref PhaseHook[void*] hooks, void* h, CPhaseCb cb) nothrow
    {
        auto p = h in hooks;
        if (p is null)
        {
            registerHook(hooks, h);
            p = h in hooks;
        }
        p.cb = cb;
        p.active = true;
        poke(); // force an iteration so the hook runs promptly (e.g. flush a send)
    }

    private void stopHook(ref PhaseHook[void*] hooks, void* h) nothrow
    {
        if (auto p = h in hooks)
            p.active = false;
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
        UdpState udp;
        if (auto st = key in udps)
        {
            udp = *st;
            udp.closing = true; // no new sends; the drain fiber stops after its current one
            udp.receiving = false; // the reader stops after its current datagram
            // The UDPConnection stays open until drainCloses has stopped both fibers:
            // closing it here (possibly inside a libudx callback, possibly on the reader
            // itself) would strand a parked recv. Deferred to the loop instead.
            udps.remove(key);
        }
        timers.remove(key);
        prepares.remove(key);
        checks.remove(key);
        h.active = 0;
        h.closing = 1;
        // libuv's contract: every request on the handle completes or is cancelled
        // BEFORE the handle's close callback. The pending close carries the UDP
        // state so drainCloses can settle its send queue first (and wait for the
        // drain fiber to finish the one send it may have in flight).
        if (cb !is null || udp !is null)
            pendingCloses ~= PendingClose(h, cb, udp);
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

// ── the __d_hsuv_* facade (C linkage, nothrow) ───────────────────────────────────
// Implemented as extern(C++, "udx") so they are udx::__d_hsuv_* — C++-mangled, NOT
// global C symbols — matching the shim's namespaced prototypes; nothing leaks.
// Every parameter is void*/int/uint/ulong/char*, mirroring the shim exactly, so
// the mangled names agree without mirroring any uv struct type in D.

private noreturn nyi(string what) nothrow
{
    assert(0, what);
}

// ── private helpers of the shim (D linkage; must stay out of the C/C++ block) ──
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

// The tasks currently running libudx callbacks off the loop task: the UDP readers and
// send drains for their whole life, and any task inside a stream close callback (a
// Connection.destroy() on an ordinary task reaches onClose synchronously). Their
// callbacks can reach application code that starts a blocking shutdown; see
// insideUdxCallback. One entry per enter (they nest).
private Task[] ioTasks;

// Tasks inside a stream close callback right now (one entry per frame; they nest).
// Unlike ioTasks these frames END: a shutdown waits for them (udxCallbacksActive),
// because libudx only queues the stream's finalizer handles after its callback returns.
private Task[] callbackFrames;

/// Mark the calling task as inside a udx callback until the matching udxCallbackLeave.
void udxCallbackEnter() nothrow
{
    callbackFrames ~= Task.getThis();
}

/// ditto
void udxCallbackLeave() nothrow
{
    auto me = Task.getThis();
    foreach (i, t; callbackFrames)
        if (t == me)
        {
            callbackFrames = callbackFrames[0 .. i] ~ callbackFrames[i + 1 .. $];
            return;
        }
}

/// Whether some task is still inside a stream close callback (see callbackFrames).
bool udxCallbacksActive() nothrow
{
    return callbackFrames.length != 0;
}

private void enterIoTask() nothrow
{
    ioTasks ~= Task.getThis();
}

private void leaveIoTask() nothrow
{
    auto me = Task.getThis();
    foreach (i, t; ioTasks)
        if (t == me)
        {
            ioTasks = ioTasks[0 .. i] ~ ioTasks[i + 1 .. $];
            return;
        }
}

/// Whether the calling task is inside a udx callback (a UDP reader or send drain, or a
/// stream close callback). A shutdown started from there must not block on the loop: the
/// loop cannot finish closing that socket until this very frame returns.
bool insideUdxCallback() nothrow
{
    auto me = Task.getThis();
    foreach (t; ioTasks)
        if (t == me)
            return true;
    foreach (t; callbackFrames)
        if (t == me)
            return true;
    return false;
}

private void readerLoop(UdpState st) nothrow
{
    enterIoTask();
    scope (exit)
    {
        leaveIoTask();
        if (st.closing)
            st.loop.poke(); // a close is waiting for this reader to exit
    }
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

private void drainSends(UdpState st) nothrow
{
    enterIoTask();
    scope (exit)
    {
        leaveIoTask();
        if (st.aborting && !st.closing)
            cancelSends(st); // shutdown: nothing more goes out on this socket
        st.draining = false;
        if (st.closing)
            st.loop.poke(); // let drainCloses settle the rest and run the close cb
    }
    while (st.sendQueue.length && !st.closing && !st.aborting)
    {
        auto s = st.sendQueue[0];
        st.sendQueue = st.sendQueue[1 .. $];
        int status = 0;
        try
            st.conn.send(s.data, &s.peer);
        catch (Exception)
            status = st.closing || st.aborting ? UV_ECANCELED : -1;
        if (s.cb !is null)
            s.cb(s.req, status);
    }
}

// The handle is closing: every send still queued completes with UV_ECANCELED,
// in order, before the handle's close callback (libuv semantics).
private void cancelSends(UdpState st) nothrow
{
    auto q = st.sendQueue;
    st.sendQueue = null;
    foreach (s; q)
        if (s.cb !is null)
            s.cb(s.req, UV_ECANCELED);
}

private int hookInit(void* loop, void* handle, int type) nothrow
{
    auto h = cast(uv_handle_t*) handle;
    h.loop = cast(uv_loop_t*) loop;
    h.type = type;
    h.active = 0;
    h.closing = 0;
    auto lp = loopOf(loop);
    lp.registerHook(type == UV_PREPARE ? lp.prepares : lp.checks, handle);
    return 0;
}


/// The __d_hsuv_* shim: the libuv surface libudx calls, provided by D. libudx is built
/// as plain C on every target (vendor/build-libudx.sh) and references these as C
/// symbols; every libudx internal is localized by the linker there, so nothing but
/// hs_udx_* and these __d_hsuv_* names cross the C/D boundary.
extern (C):

// ── loop / time ──────────────────────────────────────────────────────────────
ulong __d_hsuv_now(const(void)* loop) nothrow
{
    // Fresh, not the per-iteration cache libuv keeps: here the socket reader and
    // the loop are different fibers, so an ack can be processed while the loop
    // fiber is parked in its wait and its cached clock is stale — libudx then
    // sees zero RTTs and a frozen token-bucket refill, and BBR paces to a crawl.
    auto l = loopOf(cast(void*) loop);
    l.updateNow();
    return l.nowMs;
}

ulong __d_hsuv_hrtime() nothrow
{
    immutable t = MonoTime.currTime.ticks;
    immutable freq = MonoTime.ticksPerSecond;
    return cast(ulong)(t / freq) * 1_000_000_000UL
        + cast(ulong)((t % freq) * 1_000_000_000UL / freq);
}

// ── buffers ──────────────────────────────────────────────────────────────────
uv_buf_t __d_hsuv_buf_init(char* base, uint len) nothrow
{
    return uv_buf_t(base, len);
}

// ── handles ──────────────────────────────────────────────────────────────────
void __d_hsuv_close(void* handle, void* close_cb) nothrow
{
    auto h = cast(uv_handle_t*) handle;
    if (h.loop !is null)
        loopOf(cast(void*) h.loop).closeHandle(h, cast(CCloseCb) close_cb);
}

int __d_hsuv_is_active(const(void)* handle) nothrow
{
    return (cast(uv_handle_t*) handle).active;
}

int __d_hsuv_fileno(const(void)* handle, int* fd) nothrow
{
    auto st = udpOf(cast(uv_handle_t*) handle);
    if (st is null || !st.bound)
        return UV_EINVAL;
    *fd = st.fd;
    return 0;
}

int __d_hsuv_recv_buffer_size(void* handle, int* value) nothrow
{
    return bufferSize(cast(uv_handle_t*) handle, SO_RCVBUF, value);
}

int __d_hsuv_send_buffer_size(void* handle, int* value) nothrow
{
    return bufferSize(cast(uv_handle_t*) handle, SO_SNDBUF, value);
}

// libuv semantics: *value == 0 → get current into *value; else set it. Linux
// doubles the SO_*BUF value it stores, matching what libuv reports.

// ── timers ───────────────────────────────────────────────────────────────────
int __d_hsuv_timer_init(void* loop, void* handle) nothrow
{
    auto h = cast(uv_handle_t*) handle;
    h.loop = cast(uv_loop_t*) loop;
    h.type = UV_TIMER;
    h.active = 0;
    h.closing = 0;
    loopOf(loop).registerTimer(handle);
    return 0;
}

int __d_hsuv_timer_start(void* handle, void* cb, ulong timeout, ulong repeat) nothrow
{
    auto h = cast(uv_handle_t*) handle;
    h.active = 1;
    loopOf(cast(void*) h.loop).startTimer(handle, cast(CTimerCb) cb, timeout, repeat);
    return 0;
}

int __d_hsuv_timer_stop(void* handle) nothrow
{
    auto h = cast(uv_handle_t*) handle;
    h.active = 0;
    if (h.loop !is null)
        loopOf(cast(void*) h.loop).stopTimer(handle);
    return 0;
}

// ── UDP ──────────────────────────────────────────────────────────────────────
int __d_hsuv_udp_init(void* loop, void* handle) nothrow
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

int __d_hsuv_udp_bind(void* handle, const(void)* addr, uint flags) nothrow
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

int __d_hsuv_udp_getsockname(const(void)* handle, void* name, int* namelen) nothrow
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

int __d_hsuv_udp_recv_start(void* handle, void* alloc_cb, void* recv_cb) nothrow
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
    if (st.readerAlive())
        return 0; // the previous reader is still parked in recv: it resumes receiving
    try
        st.reader = runTask(&readerLoop, st);
    catch (Exception)
    {
        st.receiving = false; // the reader never started; leave the socket re-armable
        return UV_EINVAL;
    }
    return 0;
}

// The bridge: turn vibe's blocking recv into libuv's alloc_cb + recv_cb. Runs on
// its own fiber; the callbacks it invokes are libudx C and never yield, so they
// are atomic w.r.t. the loop runner and timers.

int __d_hsuv_udp_send(void* req, void* handle, const(void)* bufsRaw, uint nbufs, const(void)* addr, void* send_cb) nothrow
{
    auto bufs = cast(const(uv_buf_t)*) bufsRaw;
    auto st = udpOf(cast(uv_handle_t*) handle);
    if (st is null || !st.bound || st.closing)
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
        if (sendTraceOn())
            fprintf(stderr, "[facade] SLOW udp_send fd=%d bound=%d queued=%zu\n", st.fd,
                cast(int) st.conn.localAddress.port, st.sendQueue.length);
        st.sendQueue ~= PendingSend(req, data, peer, cb);
        if (!st.draining)
        {
            st.draining = true;
            try
                st.drainer = runTask(() nothrow { drainSends(st); });
            catch (Exception)
            {
                // The drain fiber never started: undo the queue mutation and report
                // failure, so libudx frees its request and no later close callbacks
                // it with a stale pointer, and the socket is not wedged un-draining.
                st.draining = false;
                if (st.sendQueue.length && st.sendQueue[$ - 1].req is req)
                    st.sendQueue = st.sendQueue[0 .. $ - 1];
                return UV_EINVAL;
            }
        }
    }
    catch (Exception)
        return UV_EINVAL;
    return 0;
}

// The one sender per socket: pops sends in order, each one blocking on a full
// socket buffer (vibe waits for writability), and fires its completion callback
// from this fiber — cooperative, so atomic with respect to libudx.

int __d_hsuv_udp_try_send(void* handle, const(void)* bufsRaw, uint nbufs, const(void)* addr) nothrow @trusted
{
    auto bufs = cast(const(uv_buf_t)*) bufsRaw;
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
    if (sendTraceOn())
        fprintf(stderr, "[facade] try_send fd=%d n=%ld errno=%d\n", st.fd,
            cast(long) n, n < 0 ? errno : 0);
    if (n < 0)
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? UV_EAGAIN : -errno;
    return cast(int) n;
}

int __d_hsuv_udp_set_ttl(void* handle, int ttl) nothrow @trusted
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

int __d_hsuv_udp_set_multicast_loop(void* handle, int on) nothrow { return 0; }
int __d_hsuv_udp_set_multicast_interface(void* handle, const(char)* interface_addr) nothrow { return 0; }
int __d_hsuv_udp_set_membership(void* handle, const(char)* multicast_addr, const(char)* interface_addr, int membership) nothrow { return 0; }
int __d_hsuv_udp_set_source_membership(void* handle, const(char)* multicast_addr, const(char)* interface_addr, const(char)* source_addr, int membership) nothrow { return 0; }

// ── prepare / check (loop-phase hooks) ───────────────────────────────────────

int __d_hsuv_prepare_init(void* loop, void* prepare) nothrow
{
    return hookInit(loop, prepare, UV_PREPARE);
}

int __d_hsuv_prepare_start(void* prepare, void* cb) nothrow
{
    auto h = cast(uv_handle_t*) prepare;
    h.active = 1;
    auto lp = loopOf(cast(void*) h.loop);
    lp.startHook(lp.prepares, prepare, cast(CPhaseCb) cb);
    return 0;
}

int __d_hsuv_prepare_stop(void* prepare) nothrow
{
    auto h = cast(uv_handle_t*) prepare;
    h.active = 0;
    auto lp = loopOf(cast(void*) h.loop);
    lp.stopHook(lp.prepares, prepare);
    return 0;
}

int __d_hsuv_check_init(void* loop, void* check) nothrow
{
    return hookInit(loop, check, UV_CHECK);
}

int __d_hsuv_check_start(void* check, void* cb) nothrow
{
    auto h = cast(uv_handle_t*) check;
    h.active = 1;
    auto lp = loopOf(cast(void*) h.loop);
    lp.startHook(lp.checks, check, cast(CPhaseCb) cb);
    return 0;
}

int __d_hsuv_check_stop(void* check) nothrow
{
    auto h = cast(uv_handle_t*) check;
    h.active = 0;
    auto lp = loopOf(cast(void*) h.loop);
    lp.stopHook(lp.checks, check);
    return 0;
}

// ── DNS ──────────────────────────────────────────────────────────────────────
int __d_hsuv_getaddrinfo(void* loop, void* req, void* cb, const(char)* node, const(char)* service, const(void)* hints) nothrow { nyi("uv_getaddrinfo"); }
void __d_hsuv_freeaddrinfo(void* ai) nothrow { nyi("uv_freeaddrinfo"); }

// ── interfaces ───────────────────────────────────────────────────────────────
int __d_hsuv_interface_addresses(void* addresses, int* count) nothrow { nyi("uv_interface_addresses"); }
void __d_hsuv_free_interface_addresses(void* addresses, int count) nothrow { nyi("uv_free_interface_addresses"); }

// ── misc ─────────────────────────────────────────────────────────────────────
const(char)* __d_hsuv_strerror(int err) nothrow
{
    // libudx only uses this for debug logging (compiled out) and assert messages;
    // a stable static string is enough. The literal is null-terminated.
    return "hsuv: udx error".ptr;
}
