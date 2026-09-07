/// The D side of the libuv→vibe facade: the `hsuv_*` functions libudx calls.
///
/// libudx's vendored C is amalgamated as one C++ TU in `namespace udx` and
/// compiled against our shim uv.h, which renames every libuv function to `hsuv_*`
/// (symbol isolation — see vendor/libudx-shim/uv.h). Those are the C-ABI symbols
/// this module defines. libudx never calls uv_run: WE drive the callbacks from a
/// vibe fiber (`Loop.run`), so there is one event loop (vibe's), single-threaded.
///
/// STATUS: loop + timers + buffers are live; UDP / prepare / check / getaddrinfo /
/// interfaces are still stubs (they assert if called). See notes/uv-facade.md.
///
/// Every `hsuv_*` function is `nothrow`: libudx is C and a D exception unwinding
/// into it would be undefined behaviour, so each catches internally and returns a
/// libuv-style negative code on failure.
module hyperswarm.udx.facade;

import core.time : MonoTime, Duration, msecs;
import vibe.core.sync : LocalManualEvent, createManualEvent;

// ── C struct layouts (must match vendor/libudx-shim/uv.h) ────────────────────

/// `uv_buf_t { char* base; size_t len; }` — for ABI-correct by-value return.
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
/// libudx only ever touches `.data`; we use `.loop`/`.impl`/`.active`. All handle
/// types share this layout, so one struct serves the facade.
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

/// A timer handle is layout-identical to the common prefix.
alias uv_timer_t = uv_handle_t;

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

/// One libuv loop, backed by vibe. libudx registers timers (and, later, UDP
/// sockets and prepare/check hooks) against it; `run` is the loop-runner a vibe
/// fiber drives: fire due timers, sleep until the next deadline or an explicit
/// wake, repeat. `uv_now` reads the cached time refreshed each turn.
final class Loop
{
    private uv_loop_t cLoop;
    private ulong nowMs;
    private MonoTime epoch;
    private TimerState[void*] timers; // keyed by the handle pointer
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
        // Collect due handles first: a callback may start/stop/close timers, and
        // we must not mutate the map mid-iteration.
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
                    continue; // already due — loop back to fire
                }
                wake.wait(dms.msecs, cnt);
            }
            else
                wake.wait(cnt); // nothing scheduled — wait for a wake
            updateNow();
        }
    }

    /// Ask the runner to exit at the next turn.
    void stop() nothrow
    {
        running = false;
        try
            wake.emit();
        catch (Exception)
        {
        }
    }

    // ── operations invoked from the hsuv_* shims ─────────────────────────────
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

    private void closeHandle(uv_handle_t* h, CCloseCb cb) nothrow
    {
        timers.remove(cast(void*) h);
        h.active = 0;
        h.closing = 1;
        if (cb !is null)
            pendingCloses ~= PendingClose(h, cb);
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
}

private Loop loopOf(void* loopPtr) nothrow
{
    return cast(Loop)(cast(uv_loop_t*) loopPtr).impl;
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
    // ns = ticks * 1e9 / ticksPerSecond, kept in integers to avoid rounding drift.
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

int hsuv_fileno(const(void)* handle, int* fd) nothrow { nyi("uv_fileno"); }
int hsuv_recv_buffer_size(void* handle, int* value) nothrow { nyi("uv_recv_buffer_size"); }
int hsuv_send_buffer_size(void* handle, int* value) nothrow { nyi("uv_send_buffer_size"); }

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
int hsuv_udp_init(void* loop, void* handle) nothrow { nyi("uv_udp_init"); }
int hsuv_udp_bind(void* handle, const(void)* addr, uint flags) nothrow { nyi("uv_udp_bind"); }
int hsuv_udp_recv_start(void* handle, void* alloc_cb, void* recv_cb) nothrow { nyi("uv_udp_recv_start"); }
int hsuv_udp_getsockname(const(void)* handle, void* name, int* namelen) nothrow { nyi("uv_udp_getsockname"); }
int hsuv_udp_send(void* req, void* handle, const(uv_buf_t)* bufs, uint nbufs, const(void)* addr, void* send_cb) nothrow { nyi("uv_udp_send"); }
int hsuv_udp_try_send(void* handle, const(uv_buf_t)* bufs, uint nbufs, const(void)* addr) nothrow { nyi("uv_udp_try_send"); }
int hsuv_udp_set_ttl(void* handle, int ttl) nothrow { nyi("uv_udp_set_ttl"); }
int hsuv_udp_set_multicast_loop(void* handle, int on) nothrow { nyi("uv_udp_set_multicast_loop"); }
int hsuv_udp_set_multicast_interface(void* handle, const(char)* interface_addr) nothrow { nyi("uv_udp_set_multicast_interface"); }
int hsuv_udp_set_membership(void* handle, const(char)* multicast_addr, const(char)* interface_addr, int membership) nothrow { nyi("uv_udp_set_membership"); }
int hsuv_udp_set_source_membership(void* handle, const(char)* multicast_addr, const(char)* interface_addr, const(char)* source_addr, int membership) nothrow { nyi("uv_udp_set_source_membership"); }

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
