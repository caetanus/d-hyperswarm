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
