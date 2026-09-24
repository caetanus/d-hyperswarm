#!/usr/bin/env bash
# Builds the vendored libudx as PLAIN C — it is C — for the host or an Android
# target, into ONE relocatable object whose only global symbols are the C-ABI
# surface D binds (hs_udx_* from vendor/libudx-amalgam/hs_udx_wrappers.c). The
# isolation is done by the LINKER, not the compiler: `ld -r` merges the objects and
# `objcopy --keep-global-symbols` localizes every other definition (udx_*, the
# internals), so nothing of libudx can collide with anything else in a process.
# The uv_* → __d_hsuv_* rename is vendor/libudx-shim/uv.h (the libuv facade D provides,
# extern(C)); no uv_* symbol exists in the output. libudx itself is never edited.
# The hs_udx_* surface itself is compiled with HIDDEN visibility: the static linker
# resolves it for D, but no executable or shared library built from this exports
# a single symbol with "udx" in its name (nothing to collide with, nothing to see).
#
#   ARCH=host   (default) → bin/udx_amalgam.o + bin/libhsudx.a      (dub sourceFiles)
#   ARCH=arm64|x86_64     → bin/android-<arch>/libhsudx-android.a  (NDK clang)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-host}"
case "$ARCH" in
  host)
    CC="${CC:-cc}"; LD="${LD:-ld}"; OBJCOPY="${OBJCOPY:-objcopy}"; NM="${NM:-nm}"
    OUT="${1:-$ROOT/bin}"; ARCHIVE="$OUT/libhsudx.a"; CFLAGS=(-std=c11 -O2 -fPIC -D_GNU_SOURCE -fvisibility=hidden) ;;
  arm64|x86_64)
    NDK="${ANDROID_NDK:-/opt/android-sdk/ndk/27.2.12479018}"
    TC="$NDK/toolchains/llvm/prebuilt/linux-x86_64"
    case "$ARCH" in arm64) TRIPLE=aarch64-linux-android35 ;; x86_64) TRIPLE=x86_64-linux-android35 ;; esac
    CC="$TC/bin/$TRIPLE-clang"; LD="$TC/bin/ld.lld"; OBJCOPY="$TC/bin/llvm-objcopy"; NM="$TC/bin/llvm-nm"
    OUT="${1:-$ROOT/bin/android-$ARCH}"; ARCHIVE="$OUT/libhsudx-android.a"
    CFLAGS=(-std=c11 -O2 -fPIC -D_GNU_SOURCE -fvisibility=hidden -include sys/endian.h) ;;  # bionic: ntohl lives in sys/endian.h
  *) echo "unknown ARCH=$ARCH (host|arm64|x86_64)" >&2; exit 2 ;;
esac
mkdir -p "$OUT"; OBJ="$OUT/udx-obj"; mkdir -p "$OBJ"
INC=(-I"$ROOT/vendor/libudx-shim" -I"$ROOT/vendor/libudx/include" -I"$ROOT/vendor/libudx/src")
# skip ONLY io_win.c (Windows I/O); win_filter*.c are the windowed min/max filters
# udx_bbr.c calls — NOT Windows code, must be included
for s in cirbuf endian io_posix queue udx udx_bbr udx_rate win_filter win_filter_f64; do
  "$CC" "${CFLAGS[@]}" "${INC[@]}" -w -c "$ROOT/vendor/libudx/src/$s.c" -o "$OBJ/$s.o"
done
"$CC" "${CFLAGS[@]}" "${INC[@]}" -c "$ROOT/vendor/libudx-amalgam/hs_udx_wrappers.c" -o "$OBJ/hs_udx_wrappers.o"
# the surface that stays global: what the wrappers define
"$NM" --defined-only -g "$OBJ/hs_udx_wrappers.o" | awk '{print $3}' | sort -u > "$OBJ/keep.txt"
"$LD" -r -o "$OUT/udx_amalgam.o" "$OBJ"/*.o
"$OBJCOPY" --keep-global-symbols="$OBJ/keep.txt" "$OUT/udx_amalgam.o"
rm -f "$ARCHIVE"; "${AR:-${TC:+$TC/bin/llvm-ar}}" rcs "$ARCHIVE" "$OUT/udx_amalgam.o" 2>/dev/null || ar rcs "$ARCHIVE" "$OUT/udx_amalgam.o"
# proof: no uv_*/udx_* global, only hs_udx_* defined globals
if "$NM" -g --defined-only "$OUT/udx_amalgam.o" | awk '{print $3}' | grep -vE '^hs_udx_' | grep -q .; then
  echo "build-libudx: FATAL — a non-hs_udx_ global leaked:" >&2; "$NM" -g --defined-only "$OUT/udx_amalgam.o" | awk '{print $3}' | grep -vE '^hs_udx_' >&2; exit 1
fi
if "$NM" "$OUT/udx_amalgam.o" | grep -qE ' [A-Za-z] uv_'; then echo "build-libudx: FATAL — a uv_ symbol leaked" >&2; exit 1; fi
if "$NM" -g --defined-only "$OUT/udx_amalgam.o" 2>/dev/null | grep -qE ' [TDBR] hs_udx_' && command -v readelf >/dev/null && [ "$ARCH" = host ]; then
  if readelf -s "$OUT/udx_amalgam.o" | grep -E ' (FUNC|OBJECT) .* hs_udx_' | grep -qv HIDDEN; then echo "build-libudx: FATAL — an hs_udx_ symbol is not HIDDEN" >&2; exit 1; fi
fi
echo "build-libudx[$ARCH]: $ARCHIVE — $(wc -l < "$OBJ/keep.txt") hs_udx_* symbols (hidden, static-link only), everything else local"
