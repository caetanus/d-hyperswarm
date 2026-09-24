/* hs_udx_wrappers.c — the amalgam's extern "C" hs_udx_* forwarders, as PLAIN C
 * for the Android/NDK build (clang has no g++ -fpermissive, so libudx is compiled
 * as C, not the C++ namespace amalgam). Same bodies, udx:: stripped: the udx_*
 * they call are the global C symbols from the raw .c compiled beside this.
 * Generated from vendor/libudx-amalgam/udx_amalgam.cpp — keep in sync. */
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <uv.h>        /* shim: uv_loop_t/uv_buf_t; uv_* #defined to __d_hsuv_* */
#include "udx.h"       /* udx_* decls, udx_t, callback typedefs */


size_t hs_udx_sizeof_udx (void) { return sizeof(udx_t); }
size_t hs_udx_sizeof_socket (void) { return sizeof(udx_socket_t); }
size_t hs_udx_sizeof_stream (void) { return sizeof(udx_stream_t); }

int hs_udx_init (uv_loop_t *loop, void *udx, void *on_idle) {
  return udx_init(loop, (udx_t *) udx, (udx_idle_cb) on_idle);
}

int hs_udx_socket_init (void *u, void *s, void *close_cb) {
  return udx_socket_init((udx_t *) u, (udx_socket_t *) s, (udx_socket_close_cb) close_cb);
}
int hs_udx_socket_bind (void *s, const struct sockaddr *addr, unsigned int flags) {
  return udx_socket_bind((udx_socket_t *) s, addr, flags);
}
int hs_udx_socket_getsockname (void *s, struct sockaddr *name, int *name_len) {
  return udx_socket_getsockname((udx_socket_t *) s, name, name_len);
}
int hs_udx_socket_close (void *s) {
  return udx_socket_close((udx_socket_t *) s);
}
size_t hs_udx_sizeof_socket_send (void) { return sizeof(udx_socket_send_t); }
int hs_udx_socket_send (void *req, void *s, const uv_buf_t bufs[], unsigned int bufs_len, const struct sockaddr *addr, void *cb) {
  return udx_socket_send((udx_socket_send_t *) req, (udx_socket_t *) s, bufs, bufs_len, addr,
                             (udx_socket_send_cb) cb);
}
int hs_udx_socket_send_ttl (void *req, void *s, const uv_buf_t bufs[], unsigned int bufs_len, const struct sockaddr *addr, int ttl, void *cb) {
  return udx_socket_send_ttl((udx_socket_send_t *) req, (udx_socket_t *) s, bufs, bufs_len, addr, ttl,
                                 (udx_socket_send_cb) cb);
}
int hs_udx_socket_recv_start (void *s, void *recv_cb) {
  return udx_socket_recv_start((udx_socket_t *) s, (udx_socket_recv_cb) recv_cb);
}

int hs_udx_stream_init (void *u, void *stream, uint32_t local_id, void *close_cb, void *finalize_cb) {
  return udx_stream_init((udx_t *) u, (udx_stream_t *) stream, local_id,
                             (udx_stream_close_cb) close_cb, (udx_stream_finalize_cb) finalize_cb);
}
int hs_udx_stream_connect (void *stream, void *socket, uint32_t remote_id, const struct sockaddr *remote_addr) {
  return udx_stream_connect((udx_stream_t *) stream, (udx_socket_t *) socket, remote_id, remote_addr);
}
int hs_udx_stream_change_remote (void *stream, void *socket, uint32_t remote_id, const struct sockaddr *remote_addr, void *remote_changed_cb) {
  return udx_stream_change_remote((udx_stream_t *) stream, (udx_socket_t *) socket, remote_id, remote_addr,
                                      (udx_stream_remote_changed_cb) remote_changed_cb);
}
int hs_udx_stream_firewall (void *stream, void *firewall_cb) {
  return udx_stream_firewall((udx_stream_t *) stream, (udx_stream_firewall_cb) firewall_cb);
}
int hs_udx_stream_read_start (void *stream, void *cb) {
  return udx_stream_read_start((udx_stream_t *) stream, (udx_stream_read_cb) cb);
}
int hs_udx_stream_write_sizeof (int nwbufs) {
  return udx_stream_write_sizeof(nwbufs);
}
int hs_udx_stream_write (void *req, void *stream, const uv_buf_t bufs[], unsigned int bufs_len, void *ack_cb) {
  return udx_stream_write((udx_stream_write_t *) req, (udx_stream_t *) stream, bufs, bufs_len,
                              (udx_stream_ack_cb) ack_cb);
}
int hs_udx_stream_destroy (void *stream) {
  return udx_stream_destroy((udx_stream_t *) stream);
}

