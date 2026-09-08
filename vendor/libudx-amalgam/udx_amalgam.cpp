// SQLite-style amalgamation of the vendored libudx, enclosed in a C++ namespace.
//
// libudx's C is compiled here as C++ (g++ -fpermissive) inside `namespace udx`,
// so every libudx symbol is mangled under `udx::` and none leaks as a global C
// symbol — full enclosure, no conflict, and libudx stays vendored (not laundered).
// D calls the public API via `extern(C++, "udx")`.
//
// Two rules make this work:
//   1. System headers are hoisted to GLOBAL scope below. Their re-includes inside
//      the namespace are include-guard no-ops, so libc decls (memcpy, htons, …)
//      stay global with C linkage rather than being pulled into `udx::` (which
//      would leave them undefined at link).
//   2. The uv facade (<uv.h>) is included globally too; its declarations are
//      `extern "C"` (guarded in the header) and its function names are #defined to
//      hsuv_*, so libudx's uv calls resolve to the global C hsuv_* the D facade
//      provides — the one boundary that is deliberately NOT namespaced.
//
// The only edit to libudx's source is a block scope around one variable in
// udx_bbr.c (C++ forbids a goto past an initializer); `new` (a C++ keyword used as
// an identifier in three files) is renamed here via a scoped macro, touching no file.

// ── hoisted system headers (global scope, C linkage) ─────────────────────────
#include <assert.h>
#include <inttypes.h>
#include <math.h>
#include <stdalign.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

// The uv→vibe facade: global, extern "C", names #defined to hsuv_* (see the shim).
#include <uv.h>

// ── the library, enclosed ────────────────────────────────────────────────────
namespace udx {

#include "cirbuf.c"
#include "endian.c"

// `new` is a C++ keyword; these three files use it as an ordinary identifier.
// The macro renames only the identifier tokens (comments/strings are untouched),
// so no source file is modified.
#define new udx_new
#include "queue.c"
#include "win_filter.c"
#include "win_filter_f64.c"
#undef new

#include "io_posix.c"
#include "udx_rate.c"
#include "udx_bbr.c"
#include "udx.c"

} // namespace udx

// ── controlled C-ABI surface for the D binding ───────────────────────────────
// Thin forwarders to the udx:: API. This is the ONLY set of global C symbols the
// amalgamation exposes for udx (everything else stays under udx::); D calls these
// via extern(C) with opaque void* pointers, so it never touches C++ mangling.
// Sizes let D allocate the opaque structs without mirroring their layout.
extern "C" {

size_t hs_udx_sizeof_udx (void) { return sizeof(udx::udx_t); }
size_t hs_udx_sizeof_socket (void) { return sizeof(udx::udx_socket_t); }
size_t hs_udx_sizeof_stream (void) { return sizeof(udx::udx_stream_t); }

int hs_udx_init (uv_loop_t *loop, void *udx, void *on_idle) {
  return udx::udx_init(loop, (udx::udx_t *) udx, (udx::udx_idle_cb) on_idle);
}

int hs_udx_socket_init (void *u, void *s, void *close_cb) {
  return udx::udx_socket_init((udx::udx_t *) u, (udx::udx_socket_t *) s, (udx::udx_socket_close_cb) close_cb);
}
int hs_udx_socket_bind (void *s, const struct sockaddr *addr, unsigned int flags) {
  return udx::udx_socket_bind((udx::udx_socket_t *) s, addr, flags);
}
int hs_udx_socket_getsockname (void *s, struct sockaddr *name, int *name_len) {
  return udx::udx_socket_getsockname((udx::udx_socket_t *) s, name, name_len);
}
int hs_udx_socket_close (void *s) {
  return udx::udx_socket_close((udx::udx_socket_t *) s);
}
size_t hs_udx_sizeof_socket_send (void) { return sizeof(udx::udx_socket_send_t); }
int hs_udx_socket_send (void *req, void *s, const uv_buf_t bufs[], unsigned int bufs_len, const struct sockaddr *addr, void *cb) {
  return udx::udx_socket_send((udx::udx_socket_send_t *) req, (udx::udx_socket_t *) s, bufs, bufs_len, addr,
                             (udx::udx_socket_send_cb) cb);
}
int hs_udx_socket_recv_start (void *s, void *recv_cb) {
  return udx::udx_socket_recv_start((udx::udx_socket_t *) s, (udx::udx_socket_recv_cb) recv_cb);
}

int hs_udx_stream_init (void *u, void *stream, uint32_t local_id, void *close_cb, void *finalize_cb) {
  return udx::udx_stream_init((udx::udx_t *) u, (udx::udx_stream_t *) stream, local_id,
                             (udx::udx_stream_close_cb) close_cb, (udx::udx_stream_finalize_cb) finalize_cb);
}
int hs_udx_stream_connect (void *stream, void *socket, uint32_t remote_id, const struct sockaddr *remote_addr) {
  return udx::udx_stream_connect((udx::udx_stream_t *) stream, (udx::udx_socket_t *) socket, remote_id, remote_addr);
}
int hs_udx_stream_read_start (void *stream, void *cb) {
  return udx::udx_stream_read_start((udx::udx_stream_t *) stream, (udx::udx_stream_read_cb) cb);
}
int hs_udx_stream_write_sizeof (int nwbufs) {
  return udx::udx_stream_write_sizeof(nwbufs);
}
int hs_udx_stream_write (void *req, void *stream, const uv_buf_t bufs[], unsigned int bufs_len, void *ack_cb) {
  return udx::udx_stream_write((udx::udx_stream_write_t *) req, (udx::udx_stream_t *) stream, bufs, bufs_len,
                              (udx::udx_stream_ack_cb) ack_cb);
}
int hs_udx_stream_destroy (void *stream) {
  return udx::udx_stream_destroy((udx::udx_stream_t *) stream);
}

} // extern "C"
