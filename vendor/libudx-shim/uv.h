// Our libuv facade header. libudx is written against libuv; we do NOT use libuv.
// We compile libudx's vendored C against THIS header and implement the ~31-function
// subset it actually calls on top of vibe-core (see notes/uv-facade.md).
//
// Because we own this header, the uv structs carry only what libudx touches: a `.data`
// back-pointer plus our own opaque `impl` slot; libudx treats the handles as opaque and
// never reads their internals. All handles share an identical initial layout so the
// casts to `uv_handle_t*` in uv_close/uv_is_active/uv_fileno/uv_*_buffer_size work.
//
// This is the "header milestone": it must be complete enough that every vendored
// src/*.c compiles against it. Behaviour (the implementations) comes after.
#ifndef UV_H
#define UV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>       // libudx's debug.h uses fprintf; the real uv.h pulls this in
#include <sys/types.h>   // ssize_t
#include <sys/socket.h>  // struct sockaddr, sockaddr_storage
#include <netinet/in.h>  // struct sockaddr_in, sockaddr_in6
#include <netdb.h>       // struct addrinfo
#include <errno.h>

// ── symbol isolation ─────────────────────────────────────────────────────────
// The facade FUNCTIONS are the only symbols that could clash with a real libuv if
// one is ever linked into the same binary (the udx_* symbols are unique to libudx;
// the uv types and UV_E* codes are compile-time only and emit no symbols). We prefix
// the function names to hsuv_* so the facade exposes no global uv_* symbol. The
// preprocessor rewrites whole tokens, so both these declarations and libudx's own
// calls become hsuv_*; our D implementation exports hsuv_*. libudx's source is
// untouched. (uv_close_cb etc. are distinct tokens and are NOT affected.)
#define uv_now                          hsuv_now
#define uv_hrtime                       hsuv_hrtime
#define uv_buf_init                     hsuv_buf_init
#define uv_close                        hsuv_close
#define uv_is_active                    hsuv_is_active
#define uv_fileno                       hsuv_fileno
#define uv_recv_buffer_size             hsuv_recv_buffer_size
#define uv_send_buffer_size             hsuv_send_buffer_size
#define uv_udp_init                     hsuv_udp_init
#define uv_udp_bind                     hsuv_udp_bind
#define uv_udp_recv_start               hsuv_udp_recv_start
#define uv_udp_getsockname              hsuv_udp_getsockname
#define uv_udp_send                     hsuv_udp_send
#define uv_udp_try_send                 hsuv_udp_try_send
#define uv_udp_set_ttl                  hsuv_udp_set_ttl
#define uv_udp_set_multicast_loop       hsuv_udp_set_multicast_loop
#define uv_udp_set_multicast_interface  hsuv_udp_set_multicast_interface
#define uv_udp_set_membership           hsuv_udp_set_membership
#define uv_udp_set_source_membership    hsuv_udp_set_source_membership
#define uv_timer_init                   hsuv_timer_init
#define uv_timer_start                  hsuv_timer_start
#define uv_timer_stop                   hsuv_timer_stop
#define uv_prepare_init                 hsuv_prepare_init
#define uv_prepare_start                hsuv_prepare_start
#define uv_prepare_stop                 hsuv_prepare_stop
#define uv_check_init                   hsuv_check_init
#define uv_check_start                  hsuv_check_start
#define uv_check_stop                   hsuv_check_stop
#define uv_getaddrinfo                  hsuv_getaddrinfo
#define uv_freeaddrinfo                 hsuv_freeaddrinfo
#define uv_interface_addresses          hsuv_interface_addresses
#define uv_free_interface_addresses     hsuv_free_interface_addresses
#define uv_strerror                     hsuv_strerror

// ── error codes ──────────────────────────────────────────────────────────────
// libuv's convention on Unix: negative errno, with UV_EOF a sentinel. libudx only
// compares return codes against these, and our facade returns the same constants,
// so internal consistency is what matters; we still mirror libuv's values.
#define UV_EOF        (-4095)
#define UV_EAGAIN     (-EAGAIN)
#define UV_EALREADY   (-EALREADY)
#define UV_EBADF      (-EBADF)
#define UV_EBUSY      (-EBUSY)
#define UV_ECANCELED  (-ECANCELED)
#define UV_ECONNRESET (-ECONNRESET)
#define UV_EFAULT     (-EFAULT)
#define UV_EINVAL     (-EINVAL)
#define UV_EISCONN    (-EISCONN)
#define UV_ENOTCONN   (-ENOTCONN)
#define UV_ENOTSOCK   (-ENOTSOCK)
#define UV_EPIPE      (-EPIPE)
#define UV_ETIMEDOUT  (-ETIMEDOUT)

// uv_udp recv flag: the datagram was truncated.
#define UV_UDP_PARTIAL 2

// ── simple types ─────────────────────────────────────────────────────────────
typedef int uv_os_fd_t;
typedef int uv_os_sock_t;

typedef enum { UV_LEAVE_GROUP = 0, UV_JOIN_GROUP } uv_membership;

typedef enum {
  UV_UNKNOWN_HANDLE = 0,
  UV_HANDLE,
  UV_UDP,
  UV_TIMER,
  UV_PREPARE,
  UV_CHECK,
  UV_HANDLE_TYPE_MAX
} uv_handle_type;

typedef struct uv_loop_s uv_loop_t;
typedef struct uv_handle_s uv_handle_t;
typedef struct uv_udp_s uv_udp_t;
typedef struct uv_timer_s uv_timer_t;
typedef struct uv_prepare_s uv_prepare_t;
typedef struct uv_check_s uv_check_t;
typedef struct uv_udp_send_s uv_udp_send_t;
typedef struct uv_getaddrinfo_s uv_getaddrinfo_t;
typedef struct uv_interface_address_s uv_interface_address_t;

typedef struct uv_buf_t {
  char *base;
  size_t len;
} uv_buf_t;

// ── callbacks ────────────────────────────────────────────────────────────────
typedef void (*uv_close_cb)(uv_handle_t *handle);
typedef void (*uv_alloc_cb)(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
typedef void (*uv_timer_cb)(uv_timer_t *handle);
typedef void (*uv_prepare_cb)(uv_prepare_t *handle);
typedef void (*uv_check_cb)(uv_check_t *handle);
typedef void (*uv_udp_send_cb)(uv_udp_send_t *req, int status);
typedef void (*uv_udp_recv_cb)(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags);
typedef void (*uv_getaddrinfo_cb)(uv_getaddrinfo_t *req, int status, struct addrinfo *res);

// ── handles ──────────────────────────────────────────────────────────────────
// Every handle begins with this identical prefix; `data` is libudx's back-pointer,
// `impl` points at the GC-pinned D object that holds the vibe resource. The C side
// never dereferences `impl`; only our extern(C) functions do.
#define UV_HANDLE_FIELDS \
  void *data;            \
  uv_loop_t *loop;       \
  uv_handle_type type;   \
  int uv__active;        \
  int uv__closing;       \
  uv_close_cb uv__close_cb; \
  void *impl;

struct uv_loop_s {
  void *data;
  void *impl;
};

struct uv_handle_s { UV_HANDLE_FIELDS };
struct uv_udp_s { UV_HANDLE_FIELDS };
struct uv_timer_s { UV_HANDLE_FIELDS };
struct uv_prepare_s { UV_HANDLE_FIELDS };
struct uv_check_s { UV_HANDLE_FIELDS };

#define UV_REQ_FIELDS \
  void *data;         \
  void *impl;

struct uv_udp_send_s { UV_REQ_FIELDS };
struct uv_getaddrinfo_s { UV_REQ_FIELDS };

// libudx reads only `.phys_addr` (via strcmp) and `.address` (via memcmp); the rest
// mirrors libuv's layout so producing these is unsurprising.
struct uv_interface_address_s {
  char *name;
  char phys_addr[6];
  int is_internal;
  union {
    struct sockaddr_in address4;
    struct sockaddr_in6 address6;
  } address;
  union {
    struct sockaddr_in netmask4;
    struct sockaddr_in6 netmask6;
  } netmask;
};

// ── the API libudx calls (31 functions) ─────────────────────────────────────
uint64_t uv_now(const uv_loop_t *loop);
uint64_t uv_hrtime(void);

uv_buf_t uv_buf_init(char *base, unsigned int len);

void uv_close(uv_handle_t *handle, uv_close_cb close_cb);
int uv_is_active(const uv_handle_t *handle);
int uv_fileno(const uv_handle_t *handle, uv_os_fd_t *fd);
int uv_recv_buffer_size(uv_handle_t *handle, int *value);
int uv_send_buffer_size(uv_handle_t *handle, int *value);

int uv_udp_init(uv_loop_t *loop, uv_udp_t *handle);
int uv_udp_bind(uv_udp_t *handle, const struct sockaddr *addr, unsigned int flags);
int uv_udp_recv_start(uv_udp_t *handle, uv_alloc_cb alloc_cb, uv_udp_recv_cb recv_cb);
int uv_udp_getsockname(const uv_udp_t *handle, struct sockaddr *name, int *namelen);
int uv_udp_send(uv_udp_send_t *req, uv_udp_t *handle, const uv_buf_t bufs[], unsigned int nbufs, const struct sockaddr *addr, uv_udp_send_cb send_cb);
int uv_udp_try_send(uv_udp_t *handle, const uv_buf_t bufs[], unsigned int nbufs, const struct sockaddr *addr);
int uv_udp_set_ttl(uv_udp_t *handle, int ttl);
int uv_udp_set_multicast_loop(uv_udp_t *handle, int on);
int uv_udp_set_multicast_interface(uv_udp_t *handle, const char *interface_addr);
int uv_udp_set_membership(uv_udp_t *handle, const char *multicast_addr, const char *interface_addr, uv_membership membership);
int uv_udp_set_source_membership(uv_udp_t *handle, const char *multicast_addr, const char *interface_addr, const char *source_addr, uv_membership membership);

int uv_timer_init(uv_loop_t *loop, uv_timer_t *handle);
int uv_timer_start(uv_timer_t *handle, uv_timer_cb cb, uint64_t timeout, uint64_t repeat);
int uv_timer_stop(uv_timer_t *handle);

int uv_prepare_init(uv_loop_t *loop, uv_prepare_t *prepare);
int uv_prepare_start(uv_prepare_t *prepare, uv_prepare_cb cb);
int uv_prepare_stop(uv_prepare_t *prepare);

int uv_check_init(uv_loop_t *loop, uv_check_t *check);
int uv_check_start(uv_check_t *check, uv_check_cb cb);
int uv_check_stop(uv_check_t *check);

int uv_getaddrinfo(uv_loop_t *loop, uv_getaddrinfo_t *req, uv_getaddrinfo_cb cb, const char *node, const char *service, const struct addrinfo *hints);
void uv_freeaddrinfo(struct addrinfo *ai);

int uv_interface_addresses(uv_interface_address_t **addresses, int *count);
void uv_free_interface_addresses(uv_interface_address_t *addresses, int count);

const char *uv_strerror(int err);

#ifdef __cplusplus
}
#endif

#endif // UV_H
