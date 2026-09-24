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
// the function names to __d_hsuv_* so the facade exposes no global uv_* symbol. The
// preprocessor rewrites whole tokens, so both these declarations and libudx's own
// calls become __d_hsuv_*; our D implementation exports __d_hsuv_*. libudx's source is
// untouched. (uv_close_cb etc. are distinct tokens and are NOT affected.)
#define uv_now                          __d_hsuv_now
#define uv_hrtime                       __d_hsuv_hrtime
#define uv_buf_init                     __d_hsuv_buf_init
#define uv_close                        __d_hsuv_close
#define uv_is_active                    __d_hsuv_is_active
#define uv_fileno                       __d_hsuv_fileno
#define uv_recv_buffer_size             __d_hsuv_recv_buffer_size
#define uv_send_buffer_size             __d_hsuv_send_buffer_size
#define uv_udp_init                     __d_hsuv_udp_init
#define uv_udp_bind                     __d_hsuv_udp_bind
#define uv_udp_recv_start               __d_hsuv_udp_recv_start
#define uv_udp_getsockname              __d_hsuv_udp_getsockname
#define uv_udp_send                     __d_hsuv_udp_send
#define uv_udp_try_send                 __d_hsuv_udp_try_send
#define uv_udp_set_ttl                  __d_hsuv_udp_set_ttl
#define uv_udp_set_multicast_loop       __d_hsuv_udp_set_multicast_loop
#define uv_udp_set_multicast_interface  __d_hsuv_udp_set_multicast_interface
#define uv_udp_set_membership           __d_hsuv_udp_set_membership
#define uv_udp_set_source_membership    __d_hsuv_udp_set_source_membership
#define uv_timer_init                   __d_hsuv_timer_init
#define uv_timer_start                  __d_hsuv_timer_start
#define uv_timer_stop                   __d_hsuv_timer_stop
#define uv_prepare_init                 __d_hsuv_prepare_init
#define uv_prepare_start                __d_hsuv_prepare_start
#define uv_prepare_stop                 __d_hsuv_prepare_stop
#define uv_check_init                   __d_hsuv_check_init
#define uv_check_start                  __d_hsuv_check_start
#define uv_check_stop                   __d_hsuv_check_stop
#define uv_getaddrinfo                  __d_hsuv_getaddrinfo
#define uv_freeaddrinfo                 __d_hsuv_freeaddrinfo
#define uv_interface_addresses          __d_hsuv_interface_addresses
#define uv_free_interface_addresses     __d_hsuv_free_interface_addresses
#define uv_strerror                     __d_hsuv_strerror

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
#ifdef __cplusplus
}  // extern "C" — the types above are compile-time only; nothing to mangle
#endif

// ── the API libudx calls (31 functions) ─────────────────────────────────────
// SYMBOL ISOLATION, part 2: these are the only facade symbols. In the C++
// amalgamation they are declared inside `namespace HSUV_NAMESPACE` (= udx) with
// C++ linkage, so NO global uv_*/__d_hsuv_* symbol exists — the D facade implements
// them as extern(C++, "udx"). Parameters are deliberately `void*`-typed (handles,
// loop, req, addr, callbacks): the D side declares them as void* too, so the C++
// mangled names carry only void*/int/unsigned/uint64_t/char* and match trivially.
// libudx's typed arguments convert implicitly (T* -> void*; fn-ptr -> void* is a
// g++ extension, and the amalgam already builds with -fpermissive). libudx's
// source is untouched — the uv_* -> __d_hsuv_* #defines above rewrite its calls.
#if defined(__cplusplus) && defined(HSUV_NAMESPACE)
namespace HSUV_NAMESPACE {
#elif defined(__cplusplus)
extern "C" {
#endif

uint64_t uv_now(const void *loop);
uint64_t uv_hrtime(void);

uv_buf_t uv_buf_init(char *base, unsigned int len);

void uv_close(void *handle, void *close_cb);
int uv_is_active(const void *handle);
int uv_fileno(const void *handle, int *fd);
int uv_recv_buffer_size(void *handle, int *value);
int uv_send_buffer_size(void *handle, int *value);

int uv_udp_init(void *loop, void *handle);
int uv_udp_bind(void *handle, const void *addr, unsigned int flags);
int uv_udp_recv_start(void *handle, void *alloc_cb, void *recv_cb);
int uv_udp_getsockname(const void *handle, void *name, int *namelen);
int uv_udp_send(void *req, void *handle, const void *bufs, unsigned int nbufs, const void *addr, void *send_cb);
int uv_udp_try_send(void *handle, const void *bufs, unsigned int nbufs, const void *addr);
int uv_udp_set_ttl(void *handle, int ttl);
int uv_udp_set_multicast_loop(void *handle, int on);
int uv_udp_set_multicast_interface(void *handle, const char *interface_addr);
int uv_udp_set_membership(void *handle, const char *multicast_addr, const char *interface_addr, int membership);
int uv_udp_set_source_membership(void *handle, const char *multicast_addr, const char *interface_addr, const char *source_addr, int membership);

int uv_timer_init(void *loop, void *handle);
int uv_timer_start(void *handle, void *cb, uint64_t timeout, uint64_t repeat);
int uv_timer_stop(void *handle);

int uv_prepare_init(void *loop, void *prepare);
int uv_prepare_start(void *prepare, void *cb);
int uv_prepare_stop(void *prepare);

int uv_check_init(void *loop, void *check);
int uv_check_start(void *check, void *cb);
int uv_check_stop(void *check);

int uv_getaddrinfo(void *loop, void *req, void *cb, const char *node, const char *service, const void *hints);
void uv_freeaddrinfo(void *ai);

int uv_interface_addresses(void *addresses, int *count);
void uv_free_interface_addresses(void *addresses, int count);

const char *uv_strerror(int err);

#ifdef __cplusplus
}  // namespace HSUV_NAMESPACE / extern "C"
#endif

#endif // UV_H
