# The libuv→vibe facade (phase 2)

libudx is written against libuv. We do **not** run or embed libuv. Instead we compile
libudx's vendored C against **our own `uv.h`** and implement the subset of the libuv API
it uses on top of vibe-core. One event loop (vibe's), single-threaded, no cross-thread.

## Why this is tractable

- **libudx never calls `uv_run`** — the embedding app drives the loop. So *we* drive the
  callbacks from a vibe fiber; there is no foreign loop to run.
- **libudx treats uv handles as opaque except `.data`** (90 uses; it only ever sets
  `handle.data = stream/socket/handle` and passes `&handle` to uv functions). `uv_buf_t`
  is used only through `.base` / `.len`.
- Because **we own `uv.h`**, our uv structs can be laid out however we like — they need
  only a `void* data` plus whatever internal state our implementation keeps. We do not
  mirror real libuv's layout or its platform unions.

## The surface libudx actually uses (grep of vendor/libudx/src)

**Loop / time:** `uv_now(loop)` (cached ms), `uv_hrtime()` (monotonic ns).
**UDP:** `uv_udp_init`, `uv_udp_bind`, `uv_udp_recv_start`, `uv_udp_getsockname`,
`uv_udp_send`(+`uv_udp_send_t`,cb), `uv_udp_try_send`, `uv_udp_set_ttl`,
`uv_udp_set_multicast_loop/interface`, `uv_udp_set_membership`,
`uv_udp_set_source_membership`, `uv_recv_buffer_size`, `uv_send_buffer_size`.
**Timer:** `uv_timer_init/start/stop` (timeout + repeat).
**Prepare / Check** (loop-phase hooks): `uv_prepare_init/start/stop`,
`uv_check_init/start/stop`. UDX uses *prepare* to flush pending packets before the poll
and *check* to drain the specific-TTL send queue after it.
**Handle:** `uv_close`(+close_cb), `uv_is_active`, `uv_fileno`.
**Buffers:** `uv_buf_init` (and the `uv_buf_t {char* base; size_t len;}` type).
**DNS:** `uv_getaddrinfo`(+`uv_getaddrinfo_t`,cb), `uv_freeaddrinfo`.
**Interfaces:** `uv_interface_addresses`, `uv_free_interface_addresses`,
`uv_interface_address_t`.
**Misc:** `uv_strerror`, `uv_membership` enum, `uv_os_fd_t`/`uv_os_sock_t`,
`uv_handle_t`/`uv_handle_type`.

Signatures are pinned from the system `uv.h` (1.52.1) so our declarations match exactly
what udx.c calls; the return codes it checks are the libuv `int` convention (0 ok,
negative = -errno).

## Struct layout (our uv.h)

All handles share a common prefix (like libuv's `UV_HANDLE_FIELDS`) so casts to
`uv_handle_t*` in `uv_close`/`uv_is_active`/`uv_fileno` work:

```
#define UV_HANDLE_FIELDS  void* data; uv_loop_t* loop; uv_handle_type type; \
                          int active; int closing; uv_close_cb close_cb; void* impl;
```

- `uv_udp_t`   : handle prefix + `impl` → our UDP object (vibe UDPConnection + reader).
- `uv_timer_t` : handle prefix + `impl` → our timer node (deadline, repeat, cb).
- `uv_prepare_t`/`uv_check_t` : handle prefix + `impl` → our phase-hook node (cb).
- `uv_udp_send_t`/`uv_getaddrinfo_t` : request structs with `void* data` + our `impl`.
- `uv_buf_t` : `{ char* base; size_t len; }`.
- `uv_interface_address_t` : `{ char* name; ...; struct sockaddr(_in6) address; ... }`
  — the few fields UDX reads (name, address, is_internal).

`impl` points at a GC-pinned D object holding the vibe resource; the C side never touches
it, only our extern(C) functions do.

## Run model (the loop-runner fiber)

Since UDX never calls `uv_run`, our loop is a vibe fiber:

```
loop while running:
    run active PREPARE callbacks          // UDX flushes pending sends here
    timeout = min(active timer deadlines) - now   // 0 if a timer is already due
    wait until: any UDP socket readable, OR timeout, OR explicit wake   // the "poll"
    refresh loop time (uv_now cache)
    drain ready UDP datagrams → each socket's recv_cb
    fire expired timers → their cb (re-arm if repeat)
    run active CHECK callbacks            // UDX drains the TTL queue here
    invoke pending close_cbs
```

The "poll" is a select over (UDP readable | timeout | wake). Concretely: one reader
fiber per UDP socket blocks on `UDPConnection.recv` and pushes datagrams into a queue,
signalling a shared `LocalManualEvent`; the runner waits on that event with a timeout
equal to the next timer deadline (the util/select pattern from libp2p-dlang). A
`wake` is emitted whenever a timer is (re)started with a nearer deadline, or a handle
is closed, so the runner recomputes its timeout.

Stream read/write callbacks fired inside this runner are bridged to consumer fibers via
`LocalManualEvent`, exactly like the sans-io webrtc engine.

## uv → vibe mapping

| uv | vibe-core |
|---|---|
| `uv_loop_t` | our Loop: time cache, handle registry, timer heap, prepare/check lists, wake event |
| `uv_now` / `uv_hrtime` | cached `MonoTime` ms / `MonoTime` ns |
| `uv_udp_*` | `vibe.core.net` `UDPConnection` (bind/recv/send/ttl/buffer sizes) |
| `uv_udp_set_multicast_*` / `*_membership` | stub → return 0 or `-ENOSYS`; holepunch needs no multicast (revisit if a path does) |
| `uv_timer_*` | timer node in the Loop's heap, driven by the runner |
| `uv_prepare_*` / `uv_check_*` | phase-hook nodes run each runner iteration |
| `uv_close` | stop handle, schedule close_cb on the next iteration |
| `uv_fileno` | the UDP socket's fd (from vibe, or tracked at bind) |
| `uv_getaddrinfo` | `vibe.core.net` host resolution on a fiber → cb (hyperdht mostly uses explicit IPs) |
| `uv_interface_addresses` | `getifaddrs(3)` → fill the array |
| `uv_strerror` | map our negative codes to strings |

## Incremental build order (each step verifiable)

1. **Header milestone** — write `uv.h` (types + all prototypes); compile every
   `vendor/libudx/src/*.c` against it with `-c` (no link). Proves the surface is complete
   and the struct layouts are self-consistent. *No behavior yet.*
2. **Loop + timer + buf** — implement the Loop, the runner, `uv_timer_*`, `uv_buf_init`,
   time. Test: a timer fires on the vibe loop after N ms; repeat works; stop cancels.
3. **UDP** — `uv_udp_*` on `UDPConnection`. Test: two facade UDP sockets exchange a
   datagram, recv_cb fires with the right bytes/addr.
4. **prepare/check + close** — phase hooks and handle teardown. Test: prepare runs before
   poll, check after; uv_close invokes close_cb once.
5. **getaddrinfo + interfaces + strerror** — the remainder.
6. **udx echo** — link libudx, drive a `udx_stream_t` end to end over the facade
   (D↔D echo). Then phase-2 acceptance: reliable echo D↔JS over UDX.

## Open items

- Multicast/membership: expected stubbable for hyperswarm; confirm no holepunch path
  needs it before shipping the stubs.
- `uv_fileno`/buffer-size calls: check vibe exposes the raw fd for a `UDPConnection`;
  if not, bind via eventcore directly.
- Build wiring: dub `sourceFiles` for the vendored `.c` + `-I vendor/libudx/include`
  pointing at our `uv.h`, or a small CMake/Make prebuild producing `libudx.a`.
