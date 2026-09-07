/// The D side of the libuv→vibe facade: the `hsuv_*` functions libudx calls.
///
/// libudx's vendored C is compiled against our shim uv.h, which renames every
/// libuv function to `hsuv_*` (symbol isolation — see vendor/libudx-shim/uv.h).
/// Those are the symbols this module defines, with C linkage and C ABI.
///
/// STATUS: stubs. This lands the C↔D link (every `hsuv_*` libudx references is
/// resolved here) before any behaviour exists. Each stub asserts if called, so a
/// premature call is loud rather than silently wrong. The real implementations —
/// the vibe loop-runner, timers on vibe timers, UDP on UDPConnection — replace
/// these one group at a time (see notes/uv-facade.md).
module hyperswarm.udx.facade;

extern (C):

/// Matches the shim's `uv_buf_t { char* base; size_t len; }` for ABI-correct
/// by-value return / by-pointer passing.
struct uv_buf_t
{
    char* base;
    size_t len;
}

private noreturn nyi(string what)
{
    assert(0, "hsuv facade: " ~ what ~ " not implemented yet");
}

// ── loop / time ──────────────────────────────────────────────────────────────
ulong hsuv_now(const(void)* loop) { nyi("uv_now"); }
ulong hsuv_hrtime() { nyi("uv_hrtime"); }

// ── buffers ──────────────────────────────────────────────────────────────────
uv_buf_t hsuv_buf_init(char* base, uint len) { nyi("uv_buf_init"); }

// ── handles ──────────────────────────────────────────────────────────────────
void hsuv_close(void* handle, void* close_cb) { nyi("uv_close"); }
int hsuv_is_active(const(void)* handle) { nyi("uv_is_active"); }
int hsuv_fileno(const(void)* handle, int* fd) { nyi("uv_fileno"); }
int hsuv_recv_buffer_size(void* handle, int* value) { nyi("uv_recv_buffer_size"); }
int hsuv_send_buffer_size(void* handle, int* value) { nyi("uv_send_buffer_size"); }

// ── UDP ──────────────────────────────────────────────────────────────────────
int hsuv_udp_init(void* loop, void* handle) { nyi("uv_udp_init"); }
int hsuv_udp_bind(void* handle, const(void)* addr, uint flags) { nyi("uv_udp_bind"); }
int hsuv_udp_recv_start(void* handle, void* alloc_cb, void* recv_cb) { nyi("uv_udp_recv_start"); }
int hsuv_udp_getsockname(const(void)* handle, void* name, int* namelen) { nyi("uv_udp_getsockname"); }
int hsuv_udp_send(void* req, void* handle, const(uv_buf_t)* bufs, uint nbufs, const(void)* addr, void* send_cb) { nyi("uv_udp_send"); }
int hsuv_udp_try_send(void* handle, const(uv_buf_t)* bufs, uint nbufs, const(void)* addr) { nyi("uv_udp_try_send"); }
int hsuv_udp_set_ttl(void* handle, int ttl) { nyi("uv_udp_set_ttl"); }
int hsuv_udp_set_multicast_loop(void* handle, int on) { nyi("uv_udp_set_multicast_loop"); }
int hsuv_udp_set_multicast_interface(void* handle, const(char)* interface_addr) { nyi("uv_udp_set_multicast_interface"); }
int hsuv_udp_set_membership(void* handle, const(char)* multicast_addr, const(char)* interface_addr, int membership) { nyi("uv_udp_set_membership"); }
int hsuv_udp_set_source_membership(void* handle, const(char)* multicast_addr, const(char)* interface_addr, const(char)* source_addr, int membership) { nyi("uv_udp_set_source_membership"); }

// ── timers ───────────────────────────────────────────────────────────────────
int hsuv_timer_init(void* loop, void* handle) { nyi("uv_timer_init"); }
int hsuv_timer_start(void* handle, void* cb, ulong timeout, ulong repeat) { nyi("uv_timer_start"); }
int hsuv_timer_stop(void* handle) { nyi("uv_timer_stop"); }

// ── prepare / check (loop-phase hooks) ───────────────────────────────────────
int hsuv_prepare_init(void* loop, void* prepare) { nyi("uv_prepare_init"); }
int hsuv_prepare_start(void* prepare, void* cb) { nyi("uv_prepare_start"); }
int hsuv_prepare_stop(void* prepare) { nyi("uv_prepare_stop"); }
int hsuv_check_init(void* loop, void* check) { nyi("uv_check_init"); }
int hsuv_check_start(void* check, void* cb) { nyi("uv_check_start"); }
int hsuv_check_stop(void* check) { nyi("uv_check_stop"); }

// ── DNS ──────────────────────────────────────────────────────────────────────
int hsuv_getaddrinfo(void* loop, void* req, void* cb, const(char)* node, const(char)* service, const(void)* hints) { nyi("uv_getaddrinfo"); }
void hsuv_freeaddrinfo(void* ai) { nyi("uv_freeaddrinfo"); }

// ── interfaces ───────────────────────────────────────────────────────────────
int hsuv_interface_addresses(void* addresses, int* count) { nyi("uv_interface_addresses"); }
void hsuv_free_interface_addresses(void* addresses, int count) { nyi("uv_free_interface_addresses"); }

// ── misc ─────────────────────────────────────────────────────────────────────
const(char)* hsuv_strerror(int err) { nyi("uv_strerror"); }
